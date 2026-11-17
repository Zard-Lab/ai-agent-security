"""Guard: a committed GGUF model's embedded Jinja chat template carries a
sandbox-escape construct (checklist §4, new item).

A GGUF model's chat template is a Jinja template that runs on **every**
inference request to format the conversation before it reaches the model --
"the template runs" is not an extra precondition, it is what using the model
means. A template carrying an attribute-traversal/introspection primitive
(`__class__.__mro__.__subclasses__()`-style chains), the `|attr()` filter, or
a call to `eval`/`exec`/`subprocess`/`importlib`/... is a documented Jinja
server-side-template-injection sandbox escape (CWE-94), and it travels
*inside the model file itself* -- a code-review of the app's own source never
sees it.

Detection never renders, parses, or compiles the template -- it is treated as
a plain string throughout and scanned with regexes for the dangerous
constructs. The GGUF container itself is walked as a binary key-value format
with stdlib `struct` only (no `gguf`/`llama-cpp-python` package); every
declared length from the file is bounds-checked against the bytes actually
present before being used. Ported (with the stdlib-only, non-executing design
preserved, and the detection patterns carried over near-verbatim) from
Lab700xOrg/aisbom's ``aisbom/safety.py`` + ``aisbom/scanner.py``, the AIsbom
CLI's GGUF inspector, under its Apache-2.0 license.

Fires CRITICAL when the template carries a sandbox-escape token, the
`|attr()` filter, a dangerous callable, or a context-leaking object --
HIGH when the metadata block didn't fit the read budget (so "no finding"
would otherwise be reported as "clean" when the template might simply not
have been reached). The opt-outs for an audited, intentionally-committed
artifact are owner-side: an entry in the exceptions/baseline file (``agentsec-exceptions.json``,
reviewed in a diff like any source change), or the path in ``.agentsec/config.json``
(``nonproduct_paths`` demotes, ``archive_paths`` drops). There is deliberately NO
in-file marker: the artifact is the untrusted thing being judged, so a byte string
inside it is attacker-controlled and a malicious model could carry its own opt-out.

Scope, disclosed rather than silently assumed:
  * A read is capped at `_MAX_READ_BYTES` (8 MiB); a model with a vocabulary
    array large enough to push the chat template past that offset reports
    HIGH ("metadata incomplete") rather than a false "clean".
  * Only `tokenizer.chat_template` and its named variants
    (`tokenizer.chat_template.<name>`, llama.cpp's convention for a model
    shipping several templates) are inspected -- a template key under a
    different convention is not found.
  * Everything else in the GGUF container (architecture, quantization,
    license, tensor data) is read only far enough to walk past it; this
    guard reports on the chat template alone.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    read_bytes_prefix,
    rel,
)

_EXTENSIONS = (".gguf",)
_MAX_READ_BYTES = 8 * 1024 * 1024

_GGUF_MAGIC = b"GGUF"
_CHAT_TEMPLATE_KEY = "tokenizer.chat_template"

# GGUF scalar value types: struct format + byte width. BOOL is 1 byte (not 8)
# and FLOAT32 is 4 -- both appear in nearly every real model, so getting
# either width wrong desynchronizes the whole walk and silently loses every
# field after it.
_SCALAR_TYPES: dict[int, tuple[str, int]] = {
    0: ("<B", 1), 1: ("<b", 1), 2: ("<H", 2), 3: ("<h", 2),
    4: ("<I", 4), 5: ("<i", 4), 6: ("<f", 4), 7: ("<?", 1),
    10: ("<Q", 8), 11: ("<q", 8), 12: ("<d", 8),
}
_TYPE_STRING = 8
_TYPE_ARRAY = 9
_MAX_ARRAY_ELEMENTS = 50_000_000

# Ported from aisbom/safety.py: attribute-traversal/introspection primitives --
# the building blocks of every published Jinja SSTI sandbox escape.
_ESCAPE_TOKENS = (
    "__class__", "__bases__", "__base__", "__mro__", "__subclasses__",
    "__globals__", "__builtins__", "__import__", "__init__", "__code__",
    "__reduce__", "__getattribute__", "__dict__", "__loader__", "__spec__",
)
_DANGEROUS_CALLS = (
    "eval", "exec", "compile", "getattr", "setattr", "system", "popen",
    "Popen", "check_output", "subprocess", "importlib", "marshal", "pickle",
    "breakpoint",
)
_ATTR_FILTER = re.compile(r"\|\s*attr\s*\(")
# A dangerous callable reached by SUBSCRIPT and called: `x['system']('id')`. Matched in the RAW
# text, since the name is a string literal the call check strips. Written out (not built from
# `_DANGEROUS_CALLS`) so the ReDoS linter can resolve it; a test pins the two lists equal.
_SUBSCRIPT_CALL = re.compile(
    r"""\[\s*['"](eval|exec|compile|getattr|setattr|system|popen|Popen|check_output|subprocess"""
    r"""|importlib|marshal|pickle|breakpoint)['"]\s*\]\s*\("""
)
_CONTEXT_LEAKS = ("self._TemplateReference__context", "lipsum", "cycler", "joiner")
_INCLUSION = re.compile(r"\{%-?\s*(include|extends|import|from)\b")

_STANDARDS = ["OWASP-LLM:LLM01", "OWASP:A03", "CWE-94"]
# Single-character classes for `_strip_string_literals` to jump with: an opener of either kind,
# and the next quote-or-backslash inside a literal of each kind.
_ANY_QUOTE = re.compile(r"['\"]")
_SINGLE_QUOTE_STOP = re.compile(r"['\\]")
_DOUBLE_QUOTE_STOP = re.compile(r'["\\]')


def _word_pattern(token: str, *, traversed: bool = False) -> re.Pattern[str]:
    """`token` as a whole word; with `traversed`, only as a bare name followed by an attribute
    access or a subscript (`lipsum.`, `cycler[`, but not `ns.lipsum`, a `{% set joiner = ... %}`
    variable read, or a `joiner(...)` call)."""
    before, after = (r"(?<![A-Za-z0-9_.])", r"\s*[.\[]") if traversed else (r"(?<![A-Za-z0-9_])", r"(?![A-Za-z0-9_])")
    return re.compile(before + re.escape(token) + after)


def _call_pattern(token: str) -> re.Pattern[str]:
    """`token` used as a sink: an attribute CALL (`x.system(`; a bare `.system` attribute is just
    a field name, e.g. `messages[0].system`), or a bare name called or traversed (`eval(`,
    `subprocess.`)."""
    escaped = re.escape(token)
    return re.compile(
        r"(?:\.\s*" + escaped + r"\s*\()"
        r"|(?<![A-Za-z0-9_.])" + escaped + r"\s*[(.]"
    )


_ESCAPE_PATTERNS = tuple((t, _word_pattern(t)) for t in _ESCAPE_TOKENS)
_CALL_PATTERNS = tuple((t, _call_pattern(t)) for t in _DANGEROUS_CALLS)
# The private context reference is not a plausible benign name; the three Jinja globals are
# (a `{% set joiner = ',' %}` variable, or `joiner(...)`, its designed use), so they count only
# when an attribute is traversed off them, the escape shape (`cycler.__init__.__globals__`).
_LEAK_PATTERNS = tuple(
    (t, _word_pattern(t.split(".")[-1], traversed=t in ("lipsum", "cycler", "joiner")))
    for t in _CONTEXT_LEAKS
)


def _strip_comments(template: str) -> str:
    """Replace each `{# ... #}` comment with a space, leftmost-first and shortest-match. An
    unterminated `{#` is left in place: if no `#}` follows it, none follows any later opener
    either, so the rest of the template is kept as-is in one step. Linear in the template
    length (a lazy DOTALL regex re-scanned to the end from every unterminated opener)."""
    out: list[str] = []
    i = 0
    while True:
        start = template.find("{#", i)
        if start == -1:
            break
        end = template.find("#}", start + 2)
        if end == -1:
            break
        out.append(template[i:start])
        out.append(" ")
        i = end + 2
    out.append(template[i:])
    return "".join(out)


def _strip_string_literals(code: str) -> str:
    """Replace each '...' or "..." literal (a backslash escapes the next character) with a
    space. An unterminated opener is kept as a plain character and scanning resumes right
    after it, the same result a regex search gives. Once one opener of a quote kind is
    unterminated, every later opener of that kind is too (each later one was an escaped
    character of the first scan, which then continued from the same position), so that kind
    is never scanned again. At most one failed scan per quote kind keeps the walk linear."""
    out: list[str] = []
    dead: set[str] = set()
    n = len(code)
    i = 0
    plain_from = 0
    while True:
        # Jump to the next live opener (C-speed search, not a per-character Python loop).
        if not dead:
            found = _ANY_QUOTE.search(code, i)
            i = found.start() if found else -1
        elif len(dead) == 1:
            i = code.find("'" if '"' in dead else '"', i)
        else:
            break
        if i == -1:
            break
        quote = code[i]
        stop = _SINGLE_QUOTE_STOP if quote == "'" else _DOUBLE_QUOTE_STOP
        j = i + 1
        while True:  # to the closing quote, hopping over each backslash and the char it escapes
            hit = stop.search(code, j)
            if hit is None:
                j = n
                break
            if code[hit.start()] == "\\":
                j = hit.start() + 2
                continue
            j = hit.start()
            break
        if j >= n:
            dead.add(quote)
            i += 1
            continue
        out.append(code[plain_from:i])
        out.append(" ")
        i = plain_from = j + 1
    out.append(code[plain_from:])
    return "".join(out)


def _strip_literals_and_comments(template: str) -> str:
    return _strip_string_literals(_strip_comments(template))


def scan_jinja_template(template: str) -> list[str]:
    """Statically report dangerous constructs in a chat template. The
    template is a string throughout -- never rendered, parsed, or compiled."""
    if not template:
        return []
    # The WHOLE template is scanned: every pass below is linear, and the template's size is
    # already bounded by the file read cap. Cutting it (it was cut at 256 KiB, with only a
    # non-critical note) let padding hide the escape.
    threats: list[str] = []
    subject = template

    # Escape tokens and the attr filter are searched in the RAW text: an
    # `|attr('__class__')` bypass carries its payload inside a string literal.
    for token, pattern in _ESCAPE_PATTERNS:
        if pattern.search(subject):
            threats.append(f"JINJA_SANDBOX_ESCAPE: {token}")
    if _ATTR_FILTER.search(subject):
        threats.append("JINJA_ATTR_FILTER")
    for match in _SUBSCRIPT_CALL.finditer(subject):
        tag = f"JINJA_DANGEROUS_CALL: {match.group(1)}"
        if tag not in threats:
            threats.append(tag)

    # Call/context checks run with literals and comments removed, so a role
    # comparison like {% if message['role'] == 'system' %} is not a "call".
    code = _strip_literals_and_comments(subject)
    for token, pattern in _CALL_PATTERNS:
        if pattern.search(code):
            threats.append(f"JINJA_DANGEROUS_CALL: {token}")
    for token, pattern in _LEAK_PATTERNS:
        if pattern.search(code):
            threats.append(f"JINJA_CONTEXT_LEAK: {token}")
    for match in _INCLUSION.finditer(code):
        tag = f"JINJA_TEMPLATE_INCLUSION: {match.group(1)}"
        if tag not in threats:
            threats.append(tag)
    return threats


def jinja_threats_are_critical(threats: list[str]) -> bool:
    """A chat template runs on every inference request, so an escape
    primitive, the attr filter, a dangerous call, or a context leak is
    CRITICAL. Template inclusion alone needs a target to exist first."""
    return any(
        t.startswith(("JINJA_SANDBOX_ESCAPE:", "JINJA_DANGEROUS_CALL:", "JINJA_CONTEXT_LEAK:"))
        or t.startswith("JINJA_ATTR_FILTER")  # prefix, not equality: a variant tag is a suffix
        for t in threats
    )


class _Truncated(Exception):
    pass


@dataclass
class _GgufMetadata:
    """What one walk of a GGUF metadata block recovered."""

    values: dict[str, object] = field(default_factory=dict)  # scalar and string values by key
    kv_count: int = 0      # pairs the header declares
    pairs_read: int = 0    # pairs wholly walked
    # EVERY chat-template string in file order, a repeated key included: `values` keeps only the
    # last copy of a key, and readers disagree on which copy wins.
    templates: list[tuple[str, str]] = field(default_factory=list)
    truncated: bool = False  # the buffer ran out (or held an unknown type) before kv_count


def _parse_gguf_metadata(buf: bytes) -> _GgufMetadata:
    """Walk a GGUF metadata block into `{key: value}`. Every declared length
    from the file is bounds-checked before use; running out of buffer is an
    ordinary outcome (`truncated=True`), not an exception."""
    result = _GgufMetadata()
    if len(buf) < 24:
        result.truncated = True
        return result

    kv_count = int(struct.unpack("<Q", buf[16:24])[0])
    result.kv_count = kv_count
    pos = 24
    values = result.values

    def read_scalar(offset: int, val_type: int) -> tuple[object, int]:
        fmt, width = _SCALAR_TYPES[val_type]
        if offset + width > len(buf):
            raise _Truncated
        return struct.unpack(fmt, buf[offset : offset + width])[0], offset + width

    def read_string(offset: int) -> tuple[str, int]:
        if offset + 8 > len(buf):
            raise _Truncated
        length = struct.unpack("<Q", buf[offset : offset + 8])[0]
        offset += 8
        if length > len(buf) - offset:
            raise _Truncated
        return buf[offset : offset + length].decode("utf-8", errors="replace"), offset + length

    def skip_value(offset: int, val_type: int, depth: int = 0) -> int:
        if val_type in _SCALAR_TYPES:
            return read_scalar(offset, val_type)[1]
        if val_type == _TYPE_STRING:
            return read_string(offset)[1]
        if val_type == _TYPE_ARRAY:
            if depth > 8 or offset + 12 > len(buf):
                raise _Truncated
            elem_type = struct.unpack("<I", buf[offset : offset + 4])[0]
            count = int(struct.unpack("<Q", buf[offset + 4 : offset + 12])[0])
            offset += 12
            if count > _MAX_ARRAY_ELEMENTS:
                raise _Truncated
            if elem_type in _SCALAR_TYPES:
                width = _SCALAR_TYPES[elem_type][1]
                end = offset + width * count
                if end > len(buf):
                    raise _Truncated
                return end
            for _ in range(count):
                offset = skip_value(offset, elem_type, depth + 1)
            return offset
        raise _Truncated

    for _ in range(kv_count):
        try:
            key, pos = read_string(pos)
            if pos + 4 > len(buf):
                raise _Truncated
            val_type = struct.unpack("<I", buf[pos : pos + 4])[0]
            pos += 4
            if val_type == _TYPE_STRING:
                value, pos = read_string(pos)
                values[key] = value
                if value and (key == _CHAT_TEMPLATE_KEY or key.startswith(_CHAT_TEMPLATE_KEY + ".")):
                    result.templates.append((key, value))
            elif val_type in _SCALAR_TYPES:
                scalar_value, pos = read_scalar(pos, val_type)
                values[key] = scalar_value
            elif val_type == _TYPE_ARRAY:
                pos = skip_value(pos, _TYPE_ARRAY)
            else:
                raise _Truncated
            result.pairs_read += 1
        except (_Truncated, struct.error):
            result.truncated = True
            return result
    return result


def scan_gguf_bytes(blob: bytes) -> tuple[list[str], bool]:
    """Identify and scan a GGUF file's chat template(s). Returns (threats,
    metadata_truncated). Never raises, never renders the template."""
    if blob[:4] != _GGUF_MAGIC:
        return [], False
    parsed = _parse_gguf_metadata(blob)
    templates = sorted(parsed.templates)  # every copy of a repeated key is judged
    threats: list[str] = []
    seen: set[str] = set()  # beside the ordered list: list membership made distinct keys O(n^2)
    for key, template in templates:
        for threat in scan_jinja_template(template):
            # A SUFFIX tag: `jinja_threats_are_critical` reads the prefix, so a `[key] ` prefix made
            # every multi-template threat non-critical (and a key may itself contain `]`).
            tagged = threat if len(templates) == 1 else f"{threat} [{key}]"
            if tagged not in seen:
                seen.add(tagged)
                threats.append(tagged)
    return threats, parsed.truncated


class MlGgufTemplateInjectionGuard(Guard):
    id = "ml-gguf-template-injection"
    title = "Committed GGUF model's chat template carries a Jinja sandbox-escape construct"
    area = "AI agent"
    # The CRITICAL rule is a proven finding; "could not be fully scanned" is a review signal. It
    # is HIGH (it fails the default `--fail-on high` gate: fail closed on an untrusted artifact)
    # but ranks below a proven finding of the same severity.
    surfacing_rule_prefixes = ("ml-gguf-template-injection/metadata-incomplete",)

    # canary-model.gguf: a real, minimal GGUF container (magic + version +
    # zero tensors + one KV pair) whose tokenizer.chat_template names a
    # sandbox-escape chain -> fires
    # ml-gguf-template-injection/sandbox-escape.
    # Byte layout verified programmatically (struct.pack, never hand-counted) against
    # this module's own scan_gguf_bytes before being embedded here -- see the design
    # doc's "Canary verification" note.
    canary_plant = CanaryPlant(
        files={
            "canary-model.gguf": (
                "GGUF\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"
                "\x17\x00\x00\x00\x00\x00\x00\x00tokenizer.chat_template\x08\x00\x00\x00"
                ".\x00\x00\x00\x00\x00\x00\x00{{ ''.__class__.__mro__[1].__subclasses__() }}"
            ),
        },
        expects=frozenset({"ml-gguf-template-injection/sandbox-escape"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _EXTENSIONS):
            rel_path = rel(root, f)
            if is_nonproduct_path(rel_path, profile.archive_segments):
                continue
            try:
                blob, _more = read_bytes_prefix(f, _MAX_READ_BYTES)
            except OSError:
                continue
            try:
                threats, truncated = scan_gguf_bytes(blob)
            except Exception:  # one hostile file must not abort the scan of the rest
                threats, truncated = [], True
            if jinja_threats_are_critical(threats):
                out.append(self._finding(root, f, threats))
            elif truncated:  # a non-critical threat (inclusion) must not hide a cut read
                out.append(self._incomplete_finding(root, f))
        return out

    def _finding(self, root: Path, f: Path, threats: list[str]) -> Finding:
        named = ", ".join(t.split(": ", 1)[-1] for t in threats if ": " in t)[:200]
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=rel(root, f),
            message=(
                f"'{f.name}' embeds a chat template carrying a Jinja sandbox-escape "
                f"construct ({named or 'sandbox escape'}). This template runs on every "
                "inference request -- it is not an opt-in feature of using the model."
            ),
            remediation=(
                "Treat this artifact as compromised: do not load it. Re-export the model "
                "with its original, unmodified chat template, or regenerate it from a "
                "trusted source."
            ),
            rule="ml-gguf-template-injection/sandbox-escape",
            standards=list(_STANDARDS),
        )

    def _incomplete_finding(self, root: Path, f: Path) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=rel(root, f),
            message=(
                f"'{f.name}'s GGUF metadata block did not fit the read budget -- its chat "
                "template (if any) may not have been reached, so this is not a clean result."
            ),
            remediation=(
                "Re-scan with a larger read budget, or verify the file's provenance directly."
                " If the artifact is audited and intended, accept it owner-side: an entry in agentsec-exceptions.json, or its directory in .agentsec/config.json nonproduct_paths."
            ),
            rule="ml-gguf-template-injection/metadata-incomplete",
            standards=list(_STANDARDS),
        )
