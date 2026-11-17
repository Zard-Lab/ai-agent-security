"""Guard: no unsafe deserialization of untrusted data (checklist §3b).

`pickle.loads(data)` (and `dill`/`marshal`/`torch.load`/`joblib.load`/`yaml.load`
without a safe loader) execute arbitrary code as a side effect of *loading* —
so any of these on attacker-reachable bytes is remote code execution. This is
the mechanism behind the malicious-Hugging-Face-pickle vector (ATLAS T0004) and
insecure-deserialization tool payloads (CWE-502).

Fires CRITICAL on:
  * `pickle`/`cPickle`/`_pickle`/`dill`/`marshal`.`load`/`loads`,
  * `joblib.load(`,
  * `torch.load(` without `weights_only=True`,
  * `yaml.load(` without a Safe loader (`safe_load`/`SafeLoader`),
  * `from_pretrained(` with `trust_remote_code=True`,  # security: allow-unsafe-deserialize
  * (2026-07-03) Haystack's `Pipeline.load(`/`.loads(`/`.load_from_yaml(` —
    Haystack's own security policy states these "intentionally support dynamic imports
    at runtime to enable extensibility" and are unsafe-by-design on untrusted input, the
    same CWE-502 class as pickle/yaml.load under a different function name.

The fix is a non-executing format: `safetensors` for tensors, `yaml.safe_load`,
JSON/Protobuf for data; for Haystack pipelines, only load from a trusted source (never
a caller-supplied config). Suppress an audited (trusted-source) case with:

    obj = pickle.loads(blob)  # security: allow-unsafe-deserialize

JS/Node (2026-07-15): the `js-yaml` npm package's `load`/`loadAll`/`safeLoad`/
`safeLoadAll` are safe by default (v4+'s `load()` and `safeLoad()` both resolve against a
safe schema) — but any of them becomes unsafe the moment the caller passes an explicit
`schema:` option that resolves to `DEFAULT_FULL_SCHEMA` (js-yaml's own dangerous schema,
which allows `!!js/function`/`!!js/regexp`/`!!js/undefined` YAML type tags), a schema from
the `js-yaml-js-types` package (its `all`/`function` schemas re-add the same dangerous
tags), or a `.extend()` call on either. A YAML document with `!!js/function` executes
arbitrary JavaScript the moment it is loaded — the js-yaml analogue of Python's
`pickle.loads`/`yaml.load`. Sourced from GitHub CodeQL's `javascript/ql/src/Security/
CWE-502/UnsafeDeserialization.ql` + `UnsafeDeserializationCustomizations.qll`. (Note:
`node-serialize`'s `unserialize()` is a separate CodeQL query under CWE-094 Code Injection,
not this one.)

Fires CRITICAL on:

    const data = yaml.load(input, { schema: DEFAULT_FULL_SCHEMA });

Only live code counts on the JS side (#1055). The load call's `(` must be code on the shared anchor
mask (`js_code_matches`), and the schema signals (`schema:`, `DEFAULT_FULL_SCHEMA`, a js-yaml-js-types
binding) count only where the mask keeps them, so a call or schema name spelled out in a string does
not fire, while a call nested in a `${...}` substitution still does. The argument walk runs on the
same mask, so a `)` or `}` inside a string argument (a `.replace(')', '')` on the input) cannot end
it early and hide the options object.

Suppress an audited (trusted-source) file with a `// security: allow-unsafe-deserialize`
comment anywhere in it (mirrors the Python-side pragma; a string quoting it does not count, #424).
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
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_js_comments,
)

_ALWAYS = re.compile(
    r"\b(?:pickle|cPickle|_pickle|dill|marshal)\.loads?\s*\(|\bjoblib\.load\s*\("
)
_HAYSTACK_PIPELINE = re.compile(r"\bPipeline\s*\.\s*(?:load|loads|load_from_yaml)\s*\(")
# `Pipeline` is a common class name (sklearn/spaCy/Kedro/custom ETL) — scope the Haystack
# rule to files that pull in the `haystack` package, so a non-Haystack `Pipeline.load(`
# doesn't FP. (Note: this comment deliberately avoids the literal import phrasing the regex
# below matches, so the guard doesn't flag its own source.)
_HAYSTACK_IMPORT = re.compile(r"\b(?:import\s+haystack|from\s+haystack)\b")
_TORCH = re.compile(r"\btorch\.load\s*\(")
_TORCH_SAFE = re.compile(r"weights_only\s*=\s*True")
_YAML = re.compile(r"\byaml\.load\s*\(")
_YAML_SAFE = re.compile(r"safe_load|SafeLoader|CSafeLoader|Loader\s*=\s*\w*Safe\w*")
# Matches `from_pretrained(...trust_remote_code=True...)` ACROSS lines — these calls are
# overwhelmingly written multi-line (one kwarg per line). Scanned against whole-file text,
# not line-by-line, so the multi-line idiom is caught. The arg gap allows one level of
# nested parens — `from_pretrained(resolve_model(), trust_remote_code=True)` — without
# crossing the call's own closing paren. The alternation branches are disjoint on their
# first char (`[^()]` vs `\(`), so there is no catastrophic-backtracking ambiguity.
_TRUST_REMOTE_CODE = re.compile(
    r"from_pretrained\s*\((?:[^()]|\([^()]*\))*?trust_remote_code\s*=\s*True"
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-unsafe-deserialize")

# --- JS/Node (js-yaml unsafe schema) -----------------------------------------------------
# The call names CodeQL's UnsafeDeserialization.ql treats as sinks: `yaml.load(`/`yaml.loadAll(`
# require the `yaml.` prefix (the idiomatic `import yaml from 'js-yaml'` binding); `.safeLoad(`/
# `.safeLoadAll(` accept any object prefix (`jsYaml.safeLoad(`, etc.) since js-yaml's safe-by-name
# functions are commonly re-bound under an alias. A bare `\b` guards `load`/`safeLoad` so an
# unrelated `download(`/`reload(` doesn't match.
_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_JS_YAML_CALL_OPEN = re.compile(
    r"\byaml\s*\.\s*load(?:All)?\s*\(|\.\s*safeLoad(?:All)?\s*\("
)
# Signal inside the call's argument list — only an EXPLICIT schema option makes the call unsafe;
# a bare `yaml.load(data)`/`yaml.safeLoad(data)` (no schema override) uses js-yaml's own safe
# default and must stay silent.
_JS_SCHEMA_OPTION = re.compile(r"\bschema\s*:")
# `DEFAULT_FULL_SCHEMA` used directly as the schema, OR as the base of a `.extend(...)` — either
# way the resulting schema carries js-yaml's dangerous `!!js/*` tags. A `.extend()` on any OTHER
# receiver (the safe `DEFAULT_SCHEMA.extend([myCustomType])` documented in js-yaml's README) is
# NOT unsafe and must not fire — the old bare `.\s*extend\s*\(` matched every receiver and
# false-flagged that idiom CRITICAL (#395 Critical C3).
_JS_DEFAULT_FULL_SCHEMA = re.compile(r"\bDEFAULT_FULL_SCHEMA\b")
# Where a js-yaml-js-types binding is imported (`import X from`, `import { all }`, `const { all }
# = require(...)`). The captured clause is mined for identifier names below.
# The capture MUST start on a non-whitespace character and MUST stay bounded. `\s+(.+?)\s*` was
# ambiguous, because `.` matches a space too, so on the comment-blanked text this scans (see
# `_scan_js`) every whitespace run was partitioned quadratically before the trailing literal
# failed: 90+ minutes on one 281KB file, 30.8s on a 33KB one (#673). `[^\s]` makes the capture
# disjoint from the preceding `\s+`, which is the part that removes the blow-up; `[^\n;]{0,200}`
# caps the residual per-line work (a binding clause longer than 201 chars is not one we mine);
# `\b` stops `Outlet`/`reimport` anchoring an attempt at all. Bounding only ONE of the two was
# measured insufficient: both arms have the shape.
# Every piece here is load-bearing, measured on a second trigger shape the report did not name, a
# single minified line carrying many anchors (`const x = f() ` repeated). Excluding `;` is what keeps
# the capture inside one statement: with a bare `.` that line is quadratic again (1.6s at 98KB,
# hanging by 400KB). The `{0,200}` cap covers the same line with no `;` at all to terminate on, the
# `const a=1,b=2` comma-chain shape a bundler emits: unbounded it measures 0.04s / 0.57s / 8.8s at
# 7KB / 28KB / 112KB, and capped it stays linear at 0.002s / 0.014s / 0.038s. So neither may be
# relaxed to widen the capture. The cost is a disclosed false negative on a binding clause longer
# than 201 characters, pinned by test rather than left to prose; `js-yaml-js-types` exports two
# names (`all`, `function`), so a clause that long is not a shape this needs to mine.
_JS_TYPES_ESM = re.compile(
    r"""import\b\s+([^\s][^\n;]{0,200}?)\s+from\s+['"]js-yaml-js-types['"]"""
)
_JS_TYPES_CJS = re.compile(
    r"""(?:const|let|var)\b\s+([^\s][^\n;]{0,200}?)\s*=\s*require\(\s*['"]js-yaml-js-types['"]"""
)
_JS_IDENT = re.compile(r"[A-Za-z_$][\w$]*")
# ESM/CJS binding-clause keywords that are syntax, not a usable binding name.
_JS_BINDING_NONNAMES = frozenset({"as", "default"})
_JS_PRAGMA_TEXT = "security: allow-unsafe-deserialize"


def _js_types_bindings(text: str) -> set[str]:
    """Identifier names bound to the `js-yaml-js-types` import in this file.

    Only a load call whose args actually reference one of these bindings re-adds the dangerous
    `!!js/function`/`!!js/regexp` types, so scoping to the binding (not a file-wide "the package
    is imported anywhere" flag) stops the import from tainting every unrelated schema-bearing
    `yaml.load` in the same file (#395 Medium). Mines every identifier from the import/require
    binding clause (`X`, `{ all }`, `* as ns`, `X, { all }`), dropping the `as`/`default`
    keywords — a superset that a subsequent word-boundary match in the call args narrows down."""
    # Both patterns require this literal, so its absence means neither can match. Skipping the
    # scan entirely is exactly behaviour-preserving and takes the cost off every other file
    # (#673). It is not sufficient on its own: a file that DOES import the package falls
    # through to the patterns, which is why they are bounded rather than merely pre-checked.
    if "js-yaml-js-types" not in text:
        return set()
    names: set[str] = set()
    for rx in (_JS_TYPES_ESM, _JS_TYPES_CJS):
        for m in rx.finditer(text):
            for ident in _JS_IDENT.findall(m.group(1)):
                if ident not in _JS_BINDING_NONNAMES:
                    names.add(ident)
    return names


def _js_call_args_span(text: str, open_paren_idx: int) -> tuple[int, int]:
    """`(start, end)` of the argument list inside the parens opening at `open_paren_idx` (must be
    `(`), balancing nested `()`/`{}`/`[]` so a multi-line options-object argument (the dominant
    real-world `yaml.load(input, {\\n  schema: ...,\\n})` shape) is captured whole. If the brackets
    never balance (truncated/malformed source), the span runs to EOF — stays total, never raises.

    Returns offsets rather than a substring so the caller can slice both views at once. The caller
    walks the anchor mask, where string content is blank, so a `)` or `}` inside a string argument
    is not a bracket (#1055)."""
    depth = 0
    i = open_paren_idx
    n = len(text)
    while i < n:
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return open_paren_idx + 1, i
        i += 1
    return open_paren_idx + 1, n


def _js_signal_in_code(pattern: re.Pattern[str], args: str, args_mask: str) -> bool:
    """True if `pattern` matches the call's arguments where its first character is live code on the
    anchor mask (#1055). `schema: 'DEFAULT_FULL_SCHEMA.yml'` or a `note: 'schema: full'` value is
    string content, not the option; an identifier inside a `${...}` substitution is code."""
    return any(js_code_matches(pattern, args, args_mask, anchor=lambda m: m.start()))


class UnsafeDeserializationGuard(Guard):
    id = "unsafe-deserialization"
    title = "No unsafe deserialization of untrusted data"
    area = "Code safety"
    # Baseline tier: universal hygiene, applied before/regardless of stack detection.
    tier = "baseline"

    # pickle.loads on caller bytes -> unsafe-deserialization/untrusted-load.
    # Pipeline.loads(config) -> unsafe-deserialization/haystack-pipeline-load.
    # model_loader.py: from_pretrained with trust_remote_code=True -> fires
    # unsafe-deserialization/trust-remote-code-rce (CRITICAL).
    # Must NOT contain: security: allow-unsafe-deserialize pragma.
    canary_plant = CanaryPlant(
        files={
            "cache.py": (
                "import pickle\n"
                "from haystack import Pipeline\n\n\n"
                "def load(blob: bytes) -> object:\n    return pickle.loads(blob)\n\n\n"
                "def load_pipeline(config: str) -> Pipeline:\n    return Pipeline.loads(config)\n"
            ),
            "model_loader.py": (
                "from transformers import AutoModelForCausalLM\n"
                "\n"
                "\n"
                "def load_model(model_id: str):\n"
                "    return AutoModelForCausalLM.from_pretrained(model_id, trust_remote_code=True)\n"
            ),
        },
        expects=frozenset({
            "unsafe-deserialization/haystack-pipeline-load",
            "unsafe-deserialization/trust-remote-code-rce",
            "unsafe-deserialization/untrusted-load",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return (
            "python" in profile.features
            or "javascript" in profile.features
            or "typescript" in profile.features
        )

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        if "python" in profile.features:
            seen: set[Path] = set()
            for d in python_scan_dirs(root, profile):
                for f in iter_files(d, (".py",)):
                    if f in seen:
                        continue
                    seen.add(f)
                    out.extend(self._scan(root, f))
        if "javascript" in profile.features or "typescript" in profile.features:
            for f in iter_files(root, _JS_SUFFIXES):
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan_js(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        has_haystack = bool(_HAYSTACK_IMPORT.search(text))
        lines = text.splitlines()
        # The pragma is read off the same-length COMMENT-ONLY view, sliced exactly where `text` is
        # sliced (per line here, per `from_pretrained` span below), so a string on the finding's
        # own line quoting the pragma is content, not an opt-out (#424).
        view = comment_view(text, "python")
        view_lines = view.splitlines()
        for i, line in enumerate(lines, start=1):
            if line.lstrip().startswith("#") or _PRAGMA.search(view_lines[i - 1]):
                continue
            hit = (
                _ALWAYS.search(line)
                or (_TORCH.search(line) and not _TORCH_SAFE.search(line))
                or (_YAML.search(line) and not _YAML_SAFE.search(line))
            )
            if hit:
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="critical",
                        title="Unsafe deserialization of untrusted data",
                        location=f"{rel(root, f)}:{i}",
                        message=(
                            "This load executes code as a side effect of deserializing — on "
                            "attacker-reachable bytes (an upload, a downloaded model, a tool "
                            "payload) it is remote code execution."
                        ),
                        remediation=(
                            "Use a non-executing format: `safetensors` for model tensors, "
                            "`yaml.safe_load`, `torch.load(..., weights_only=True)`, or JSON/"
                            "Protobuf for data. Suppress a trusted-source case with "
                            "`# security: allow-unsafe-deserialize`."
                        ),
                        rule="unsafe-deserialization/untrusted-load",
                        standards=["OWASP:A08", "OWASP-LLM:LLM03", "OWASP-ASI:ASI05"],
                    )
                )
                continue
            if has_haystack and _HAYSTACK_PIPELINE.search(line):
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="critical",
                        title="Haystack Pipeline loaded from an untrusted source",
                        location=f"{rel(root, f)}:{i}",
                        message=(
                            "Haystack's `Pipeline.load()`/`.loads()`/`.load_from_yaml()` "
                            "intentionally support dynamic imports at runtime — loading a "
                            "pipeline definition from an untrusted source (a caller-"
                            "supplied config, an uploaded YAML file) is arbitrary code "
                            "execution, by Haystack's own documented design."
                        ),
                        remediation=(
                            "Only load pipeline definitions from a trusted, version-"
                            "controlled source — never from user input or an uploaded "
                            "file. Suppress a trusted-source case with "
                            "`# security: allow-unsafe-deserialize`."
                        ),
                        rule="unsafe-deserialization/haystack-pipeline-load",
                        standards=["OWASP:A08", "OWASP-LLM:LLM03", "OWASP-ASI:ASI05"],
                    )
                )
        # `from_pretrained(...)` is matched against whole-file text (these calls span lines).
        # The pragma may sit anywhere inside the call or trail its final line, so we test the
        # matched span extended to the end of the line holding the match — covering a trailing
        # `# security: allow-unsafe-deserialize` on either the opening or the kwarg line. The span
        # is sliced from the comment-only `view` at the same offsets, so a kwarg string quoting
        # the pragma inside the call is content (#424).
        for m in _TRUST_REMOTE_CODE.finditer(text):
            start_line = text.count("\n", 0, m.start()) + 1
            if lines[start_line - 1].lstrip().startswith("#"):
                continue  # whole call documented in a comment, not live code
            eol = text.find("\n", m.end())
            region = view[m.start():] if eol == -1 else view[m.start():eol]
            if _PRAGMA.search(region):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="critical",
                    title="from_pretrained with trust_remote_code=True — arbitrary remote code execution",  # security: allow-unsafe-deserialize
                    location=f"{rel(root, f)}:{start_line}",
                    message=(
                        "from_pretrained(trust_remote_code=True) downloads and executes arbitrary "  # security: allow-unsafe-deserialize
                        "Python from the model hub — equivalent to pip-installing arbitrary code "
                        "from an untrusted author"
                    ),
                    remediation=(
                        "Remove trust_remote_code=True or pin to a verified commit SHA and audit "
                        "the remote code manually before enabling"
                    ),
                    rule="unsafe-deserialization/trust-remote-code-rce",
                    standards=["OWASP:A08", "OWASP-LLM:LLM03", "OWASP-ASI:ASI05"],
                )
            )
        return out

    def _scan_js(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        raw = read(f)
        if pragma_present(_JS_PRAGMA_TEXT, raw, dialect="js"):
            return out
        # Scan a comment-blanked copy so a commented-out or documented example
        # (`// yaml.load(input, { schema: DEFAULT_FULL_SCHEMA })`) can't false-fire CRITICAL
        # (#395 Medium). `strip_js_comments` preserves layout, so line numbers still map.
        text = strip_js_comments(raw)
        if _JS_YAML_CALL_OPEN.search(text) is None:
            return out  # no candidate call: skip building the mask and mining the import
        # The anchor mask (#749, #1055): string content and template text blanked, `${...}`
        # substitution code kept, same layout as `text`. The call's `(` and every schema signal must
        # be code on it, and the argument walk counts brackets on it.
        mask = strip_js_comments(raw, strip_strings=True, keep_substitutions=True)
        js_types_bindings = _js_types_bindings(text)
        for m in js_code_matches(_JS_YAML_CALL_OPEN, text, mask, anchor=lambda m: m.end() - 1):
            start, end = _js_call_args_span(mask, m.end() - 1)
            args, args_mask = text[start:end], mask[start:end]
            if not _js_signal_in_code(_JS_SCHEMA_OPTION, args, args_mask):
                continue  # no explicit schema override — js-yaml's own safe default applies
            # Unsafe iff THIS call's schema resolves to a dangerous one: DEFAULT_FULL_SCHEMA
            # (used directly or as a `.extend()` base), or a js-yaml-js-types binding referenced
            # in these args. A `.extend()` of the safe DEFAULT_SCHEMA with a custom type is NOT
            # flagged, and a file-wide js-types import does not taint unrelated calls (#395 C3/M).
            uses_js_types = any(
                _js_signal_in_code(re.compile(r"\b" + re.escape(b) + r"\b"), args, args_mask)
                for b in js_types_bindings
            )
            unsafe = _js_signal_in_code(_JS_DEFAULT_FULL_SCHEMA, args, args_mask) or uses_js_types
            if not unsafe:
                continue
            start_line = text.count("\n", 0, m.start()) + 1
            out.append(
                Finding(
                    check_id=self.id,
                    severity="critical",
                    title="js-yaml load with an unsafe schema — arbitrary code execution",
                    location=f"{rel(root, f)}:{start_line}",
                    message=(
                        "This js-yaml load call passes an explicit `schema:` option that "
                        "resolves to DEFAULT_FULL_SCHEMA (or a js-yaml-js-types 'all'/'function' "
                        "schema, or a `.extend()` of either). These schemas allow "
                        "`!!js/function`/`!!js/regexp` YAML type tags that execute arbitrary "
                        "JavaScript the moment the document is loaded — on attacker-reachable "
                        "YAML this is remote code execution, the js-yaml counterpart to "
                        "Python's pickle.loads/yaml.load."
                    ),
                    remediation=(
                        "Drop the custom `schema` option — js-yaml v4's default `load()`/"
                        "`safeLoad()` schema is already safe. If a non-default schema is "
                        "genuinely needed, use `DEFAULT_SCHEMA`/`JSON_SCHEMA`/`CORE_SCHEMA`, "
                        "never `DEFAULT_FULL_SCHEMA` or a js-yaml-js-types 'all'/'function' "
                        "schema, on untrusted YAML."
                    ),
                    rule="unsafe-deserialization/js-yaml-unsafe-schema",
                    standards=["OWASP:A08", "OWASP-LLM:LLM03", "OWASP-ASI:ASI05"],
                )
            )
        return out
