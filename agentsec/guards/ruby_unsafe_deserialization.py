"""Guard: no unsafe deserialization of untrusted data in Ruby code (checklist §3b).

The Ruby counterpart to agentsec's existing (Python/JS-only) `unsafe-deserialization` guard —
same requirement (a load that *executes* the serialized payload is remote code execution on
attacker-reachable bytes), a genuinely different code surface (`Marshal`, Psych's `YAML.load`,
the `Oj` gem instead of `pickle`/`torch.load`/`js-yaml`), so it extends the same
`3b-unsafe-deserialization` checklist item rather than duplicating it. Part of agentsec's Ruby
guard family; Ruby stack detection (`ruby_scan_dirs`) and `strip_ruby_comments`
landed with `ruby-weak-crypto`.

Pattern verified against Brakeman's real source (`lib/brakeman/checks/check_deserialize.rb`,
`Brakeman::CheckDeserialize`) — the class name and file are cited for provenance; the detection
logic and test fixtures here are original, developed independently against the pattern
description, not copied or derived from Brakeman's own (Ruby) implementation.

Fires CRITICAL on:

  * **`Marshal.load(...)` / `Marshal.restore(...)`** — Ruby's native object-graph
    deserializer. It instantiates arbitrary classes and calls their hooks while loading, so
    crafted bytes are arbitrary code execution: the Ruby analogue of Python's `pickle.loads`.
    `Marshal.dump(...)` (serialization) is safe and never fires. The single-line deep-copy
    idiom `Marshal.load(Marshal.dump(obj))` also does not fire — see below.
  * **`YAML.load(...)` / `Psych.load(...)`** — Psych's *unsafe* loader can instantiate
    arbitrary Ruby objects from a crafted document (`!ruby/object:`), the mechanism behind the
    Rails YAML deserialization RCEs. `YAML.safe_load(...)` is the safe form and never fires.
  * **`Oj.object_load(...)`**, and **`Oj.load(..., mode: :object)`** — the `Oj` gem's
    object mode reconstructs arbitrary Ruby objects from JSON (`^o`/`^u` type keys), the same
    class of sink under a JSON parser's name.

**Oj scoping (deliberate, disclosed).** A bare `Oj.load(data)` with no `mode:` argument is NOT
flagged. Oj's effective mode for such a call comes from `Oj.default_options`, which may be set
in an initializer far from the call site; resolving it needs dataflow this guard does not do,
and `Oj.load` on a `:strict`/`:compat` default is ordinary, safe JSON parsing that appears in
a great deal of real Ruby code. Flagging it would be a high-volume false positive on the most
common Oj call shape, so only the two call shapes that are unambiguously object-mode *at the
call site* fire. The cost is a disclosed false negative on an app that sets
`Oj.default_options = {mode: :object}` globally.

Suppress an audited (trusted-source) case with:

    Marshal.load(cache_blob)  # security: allow-ruby-unsafe-deserialize
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_view, iter_files, read, rel, ruby_scan_dirs, strip_ruby_comments

# Ruby lets a module method be called with either `.` or `::` (`YAML::load(x)` is legal and
# still appears in older code), so every receiver pattern accepts both separators. The left
# boundary keeps an unrelated constant whose name merely ENDS in the receiver (`MyMarshal`,
# `FastYAML`) from matching a bare substring; `::`-qualified forms (`::YAML.load`) are
# intentionally still matched, same tolerance `ruby_weak_crypto._DIGEST_CONST` already takes.
_SEP = r"\s*(?:\.|::)\s*"

# `Marshal.load(` / `Marshal.restore(` — `Marshal.dump(` is serialization and is NOT a sink.
_MARSHAL = re.compile(rf"(?<![A-Za-z0-9_])Marshal{_SEP}(?:load|restore)\s*\(")
# The canonical Ruby deep-copy idiom, `Marshal.load(Marshal.dump(obj))`. The bytes are produced
# and consumed inside the same expression and never leave the process, so there is no untrusted
# input to attack with — flagging it CRITICAL would be a false positive on one of the most
# widely written lines in Ruby. Only the single-expression form is exempted: a dump whose result
# travels through a variable, a cache, or another process is not this idiom and still fires.
_MARSHAL_DEEP_COPY = re.compile(
    rf"(?<![A-Za-z0-9_])Marshal{_SEP}(?:load|restore)\s*\(\s*Marshal{_SEP}dump\s*\("
)
# `YAML.load(` / `Psych.load(`. `safe_load`/`safe_load_file` cannot match: the pattern requires
# `load` to follow the separator immediately, so `YAML.safe_load(` and `YAML.load_file(` are
# both outside it (the latter deliberately — see the design doc's FP discussion).
_YAML_LOAD = re.compile(rf"(?<![A-Za-z0-9_])(?:YAML|Psych){_SEP}load\s*\(")
# `Oj.object_load(` — Oj's dedicated object-mode entry point, unsafe regardless of options.
_OJ_OBJECT_LOAD = re.compile(rf"(?<![A-Za-z0-9_])Oj{_SEP}object_load\s*\(")
# `Oj.load(` ... plus an EXPLICIT object mode on the same line. Both halves are required: a bare
# `Oj.load(data)` stays silent (its mode comes from `Oj.default_options`, which is not resolvable
# here — see the module docstring).
_OJ_LOAD = re.compile(rf"(?<![A-Za-z0-9_])Oj{_SEP}load\s*\(")
_OJ_OBJECT_MODE = re.compile(r"(?:\bmode:\s*:object\b|:mode\s*=>\s*:object\b)")

_PRAGMA = re.compile(r"#\s*security:\s*allow-ruby-unsafe-deserialize")

_MESSAGES = {
    "marshal": (
        "Marshal deserialization",
        "`Marshal.load`/`Marshal.restore` instantiate arbitrary Ruby classes and run their "
        "hooks while loading — on attacker-reachable bytes (a cookie, a cache entry, an "
        "upload, a queue payload) this is remote code execution, the Ruby analogue of "
        "Python's `pickle.loads`.",
        "Deserialize with a non-executing format instead: `JSON.parse` for data, or "
        "`YAML.safe_load` with an explicit `permitted_classes:` list. If the bytes are "
        "genuinely trusted and internally produced, suppress with "
        "`# security: allow-ruby-unsafe-deserialize`.",
    ),
    "yaml": (
        "Unsafe YAML load (Psych)",
        "`YAML.load`/`Psych.load` is Psych's unsafe loader — a crafted document using "
        "`!ruby/object:` tags instantiates arbitrary Ruby objects as it is parsed, which is "
        "how the Rails YAML deserialization RCEs worked. On an untrusted document this is "
        "remote code execution.",
        "Use `YAML.safe_load(data)`, adding `permitted_classes:`/`aliases: true` only for the "
        "types the application genuinely needs. Suppress an audited trusted-source case with "
        "`# security: allow-ruby-unsafe-deserialize`.",
    ),
    "oj": (
        "Oj object-mode deserialization",
        "Oj's object mode (`Oj.object_load`, or `Oj.load(..., mode: :object)`) reconstructs "
        "arbitrary Ruby objects from JSON type keys rather than parsing plain data — on "
        "attacker-supplied JSON it is the same arbitrary-object-instantiation sink as "
        "`Marshal.load`.",
        "Parse untrusted JSON in a data-only mode: `Oj.load(data, mode: :strict)` (or "
        "`:compat`), or `JSON.parse`. Reserve object mode for internally produced payloads, "
        "and suppress such a case with `# security: allow-ruby-unsafe-deserialize`.",
    ),
}


class RubyUnsafeDeserializationGuard(Guard):
    id = "ruby-unsafe-deserialization"
    title = "No unsafe deserialization of untrusted data (Ruby)"
    area = "Code safety"

    # Marshal.load(blob) on a caller-supplied blob -> ruby-unsafe-deserialization/marshal-load.
    # Must NOT contain: a `security: allow-ruby-unsafe-deserialize` pragma, and the argument
    # must NOT be a `Marshal.dump(...)` call (that is the exempted deep-copy idiom).
    canary_plant = CanaryPlant(
        files={
            "session_store.rb": (
                "def restore_session(blob)\n"
                "  Marshal.load(blob)\n"
                "end\n"
            ),
        },
        expects=frozenset({"ruby-unsafe-deserialization/marshal-load"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "ruby" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in ruby_scan_dirs(root, profile):
            for f in iter_files(d, (".rb",)):
                if f in seen:
                    continue
                seen.add(f)
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        # The pragma check runs on the COMMENT-ONLY view (#424) — it IS the comment `strip_ruby_comments` below
        # would blank, so checking it after stripping would always miss it (the same ordering
        # bug the `ruby-weak-crypto` adversarial self-test caught before that guard shipped).
        view_lines = comment_view(text, "ruby").splitlines()  # same length: comments only (#424)
        # Blank comments so a documented example in a `#` note or an `=begin`/`=end` block never
        # fires. `strip_ruby_comments` preserves length and `splitlines()` count exactly, so the
        # two lists always pair up — `strict=True` documents that invariant, not just quiets the
        # linter.
        code_lines = strip_ruby_comments(text).splitlines()
        for i, (view, line) in enumerate(zip(view_lines, code_lines, strict=True), start=1):
            if _PRAGMA.search(view):
                continue
            if _MARSHAL.search(line) and not _MARSHAL_DEEP_COPY.search(line):
                out.append(self._finding(root, f, i, "marshal", "marshal-load"))
            if _YAML_LOAD.search(line):
                out.append(self._finding(root, f, i, "yaml", "yaml-unsafe-load"))
            if _OJ_OBJECT_LOAD.search(line) or (
                _OJ_LOAD.search(line) and _OJ_OBJECT_MODE.search(line)
            ):
                out.append(self._finding(root, f, i, "oj", "oj-object-mode-load"))
        return out

    def _finding(self, root: Path, f: Path, line: int, kind: str, rule: str) -> Finding:
        title, message, remediation = _MESSAGES[kind]
        return Finding(
            check_id=self.id,
            severity="critical",
            title=f"{title} of untrusted data (Ruby)",
            location=f"{rel(root, f)}:{line}",
            message=message,
            remediation=remediation,
            rule=f"{self.id}/{rule}",
            standards=["OWASP:A08"],
        )
