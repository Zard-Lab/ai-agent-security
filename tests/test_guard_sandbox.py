"""Guard Sandbox Contract drift suite — "no guard escapes the deterministic sandbox".

AST-scans every `agentsec/guards/*.py` for banned imports/calls and asserts the
contract holds. Like the canary, it also proves the alarm itself rings (a planted
banned import/call must be flagged) so a no-op scanner can't pass silently.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.guard_sandbox import SandboxReport, evaluate, scan_guards

_GUARDS_DIR = Path(__file__).resolve().parents[1] / "agentsec" / "guards"


@pytest.fixture(scope="module")
def report() -> SandboxReport:
    return scan_guards()


def test_all_existing_guards_clean(report: SandboxReport) -> None:
    # Every shipped guard module imports/calls only inside the sandbox.
    assert report.ok, f"sandbox violations: {report.violations}"


def test_scan_covers_guards_and_ai_dirs(report: SandboxReport) -> None:
    # No silent miss: every *.py in agentsec/guards/ AND agentsec/ai/ was actually
    # scanned (the dead-lint lesson — a scan that covers nothing looks clean). The
    # ai/ modules are in scope because guards delegate to them (L2).
    pkg = _GUARDS_DIR.parent
    on_disk = {
        p.relative_to(pkg).as_posix()
        for d in (_GUARDS_DIR, pkg / "ai")
        for p in d.glob("*.py")
    }
    assert on_disk, "no modules found to scan"
    assert set(report.scanned) == on_disk
    assert any(n.startswith("ai/") for n in report.scanned), "ai/ modules must be covered"


def test_evaluate_survives_recursionerror(monkeypatch: pytest.MonkeyPatch) -> None:
    # H12 contract: a RecursionError from ast.parse becomes one `unparseable` violation,
    # never a propagated crash. Force the branch via monkeypatch rather than a fixed-depth
    # binop chain — the input that overflows the parser is CPython-version-specific (3.12
    # raised at ~50k terms; 3.14 raised the parser depth, so 50k now parses and only ~200k
    # overflows), which made the old depth-coupled test fail on 3.14. See issue #320.
    def boom(_source: object) -> object:  # one positional, mirroring the ast.parse(source) call
        raise RecursionError("maximum recursion depth exceeded")
    monkeypatch.setattr("agentsec.guard_sandbox.ast.parse", boom)
    out = evaluate("x.py", "1 + 1")
    assert len(out) == 1 and out[0].kind == "unparseable"


def test_evaluate_survives_memoryerror(monkeypatch: pytest.MonkeyPatch) -> None:
    # #370: ast.parse raises MemoryError ("Parser stack overflowed") on a deeply nested but
    # parseable expression — the old (SyntaxError, RecursionError) clauses didn't catch it. The
    # shared PARSE_FAILURE_EXCEPTIONS tuple now does; the scan stays total.
    def boom(_source: object) -> object:
        raise MemoryError("Parser stack overflowed - Python source too complex to parse")
    monkeypatch.setattr("agentsec.guard_sandbox.ast.parse", boom)
    out = evaluate("x.py", "1 + 1")
    assert len(out) == 1 and out[0].kind == "unparseable"


def test_contract_flags_banned_import() -> None:
    assert any(v.kind == "import" and v.detail == "subprocess"
               for v in evaluate("x.py", "import subprocess\n"))
    assert any(v.kind == "import" and v.detail == "os"
               for v in evaluate("x.py", "from os import system\n"))
    # dotted import is matched on its root
    assert any(v.kind == "import" and v.detail == "urllib.request"
               for v in evaluate("x.py", "import urllib.request\n"))


def test_contract_flags_banned_call() -> None:
    assert any(v.kind == "call" and v.detail == "eval"
               for v in evaluate("x.py", "eval('1 + 1')\n"))
    assert any(v.kind == "call" and v.detail == "open"
               for v in evaluate("x.py", "open('/tmp/x', 'w')\n"))


def test_contract_flags_wall_clock_reads() -> None:
    # The clock ban (L1) makes "guards are pure functions of file bytes (no time)"
    # structural — the audit date is threaded via StackProfile.today, never read here.
    assert any(v.kind == "call" and v.detail == "date.today"
               for v in evaluate("x.py", "from datetime import date\nd = date.today()\n"))
    assert any(v.kind == "call" and v.detail == "datetime.now"
               for v in evaluate("x.py", "import datetime\nn = datetime.datetime.now()\n"))
    assert any(v.kind == "call" and v.detail == "time.time"
               for v in evaluate("x.py", "import time\nt = time.time()\n"))


def test_contract_flags_entropy_imports() -> None:
    assert any(v.kind == "import" and v.detail == "random"
               for v in evaluate("x.py", "import random\n"))
    assert any(v.kind == "import" and v.detail == "secrets"
               for v in evaluate("x.py", "from secrets import token_hex\n"))


def test_contract_allows_pure_date_parsing() -> None:
    # `date.fromisoformat(...)` is a PURE function of its argument — not a clock read —
    # so the supply-chain guard's waiver-expiry parsing must stay allowed.
    src = "from datetime import date\ndef f(s):\n    return date.fromisoformat(s)\n"
    assert evaluate("legit.py", src) == []


def test_contract_allows_legitimate_guard() -> None:
    # A realistic guard shape — stdlib-safe imports, relative + agentsec imports,
    # no banned builtins — must produce zero violations.
    source = (
        "from __future__ import annotations\n"
        "import re\n"
        "from pathlib import Path\n"
        "from agentsec.findings import Finding\n"
        "from .base import Guard, iter_files, read, rel\n"
        "\n"
        "class X(Guard):\n"
        "    def run(self, root, profile):\n"
        "        return []\n"
    )
    assert evaluate("legit.py", source) == []


def test_contract_relative_import_not_flagged() -> None:
    # `from . import x` (module is None, level > 0) must not crash or flag.
    assert evaluate("x.py", "from . import base\n") == []
    assert evaluate("x.py", "from .base import Guard\n") == []


def test_contract_unparseable_is_reported_not_raised() -> None:
    out = evaluate("broken.py", "def f(:\n")
    assert len(out) == 1 and out[0].kind == "unparseable"


def test_contract_deterministic(report: SandboxReport) -> None:
    again = scan_guards()
    assert again.violations == report.violations
    assert again.scanned == report.scanned


def test_is_nonproduct_path_callers_thread_archive_segments() -> None:
    # Durability gate: every guard that filters non-product paths must pass the repo's
    # opt-in `profile.archive_segments` to `is_nonproduct_path`, or the
    # `.agentsec/config.json` archive suppression silently regresses for that guard
    # (the next guard added would otherwise forget it, with nothing to catch it — the
    # same "silently stopped honoring X" class the canary guards against). Calls are
    # single-line by convention; a multi-line call would need this gate updated.
    offenders: list[str] = []
    for p in sorted(_GUARDS_DIR.glob("*.py")):
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if "def is_nonproduct_path" in line:
                continue  # the definition in base.py, not a call site
            if "is_nonproduct_path(" in line and "archive_segments" not in line:
                offenders.append(f"{p.name}:{i}")
    assert not offenders, (
        "is_nonproduct_path call(s) not threading profile.archive_segments — the archive "
        f"opt-in would silently regress for: {offenders}"
    )


# ---------------------------------------------------------------------------
# — adversarial/fuzz pass over the G2 contract itself: deliberately
# construct guard-shaped source that tries to smuggle os/subprocess/eval/file-
# write access past the scanner. Every case below is now a REGRESSION TEST (the
# scanner correctly rejects it — a passing assertion the boundary holds). Three
# cases (getattr/__builtins__, globals()/__builtins__, sys.modules) were real,
# confirmed bypasses when this fuzz pass first ran, tracked as a known gap and kept
# as `xfail` tripwires rather than silently fixed; the fix (banning
# `__builtins__` as a bare name, `globals`/`locals`/`vars` as calls, and `sys`
# as an import root — see guard_sandbox.py) closed all three, so the markers
# were removed here rather than left dead. `locals`/`vars` get their own
# regression test alongside `globals` even though only `globals` was one of the
# three originally-confirmed bypasses.
# ---------------------------------------------------------------------------


def test_fuzz_aliased_banned_import() -> None:
    # `import os as o` — the alias must not defeat root-name matching (alias.name
    # is the original dotted module name; the `as` binding is a separate field).
    assert any(v.kind == "import" and v.detail == "os"
               for v in evaluate("x.py", "import os as o\n"))


def test_fuzz_from_import_banned_module() -> None:
    assert any(v.kind == "import" and v.detail == "os"
               for v in evaluate("x.py", "from os import system\n"))


def test_fuzz_dynamic_dunder_import() -> None:
    assert any(v.kind == "call" and v.detail == "__import__"
               for v in evaluate("x.py", "__import__('os')\n"))


def test_fuzz_importlib_import_module() -> None:
    # `importlib` is itself on `_BANNED_IMPORT_ROOTS`, so the plain `import
    # importlib` statement is caught before `.import_module(...)` is ever reached
    # — confirms this specific route is closed, not merely assumed from the name.
    src = "import importlib\nimportlib.import_module('subprocess')\n"
    assert any(v.kind == "import" and v.detail == "importlib" for v in evaluate("x.py", src))


def test_fuzz_string_built_exec_import() -> None:
    # `exec`/`eval` are themselves banned CALLS, so a string-built payload inside
    # one is caught at the call site regardless of what the string contains.
    assert any(v.kind == "call" and v.detail == "exec"
               for v in evaluate("x.py", "exec('import os')\n"))


def test_fuzz_string_built_eval_import_and_call() -> None:
    assert any(v.kind == "call" and v.detail == "eval"
               for v in evaluate("x.py", "eval(\"__import__('os').system('x')\")\n"))


def test_fuzz_open_write_positional_mode() -> None:
    assert any(v.kind == "call" and v.detail == "open"
               for v in evaluate("x.py", "open('/tmp/x', 'w')\n"))


def test_fuzz_open_write_keyword_mode() -> None:
    # `open(..., mode='w')` — the call-name ban fires on the call shape itself
    # (`func.id == "open"`), never inspecting args, so the keyword form is caught
    # exactly like the positional form.
    assert any(v.kind == "call" and v.detail == "open"
               for v in evaluate("x.py", "open('/tmp/x', mode='w')\n"))


def test_fuzz_open_write_mode_via_variable() -> None:
    # A variable holding `'w'` can't launder the mode argument either — `open()`
    # itself is banned outright, not just its write-mode invocations.
    src = "m = 'w'\nopen('/tmp/x', m)\n"
    assert any(v.kind == "call" and v.detail == "open" for v in evaluate("x.py", src))


def test_fuzz_transitive_import_behind_first_party_wrapper_known_gap() -> None:
    # KNOWN, ALREADY-DISCLOSED gap — not a new finding. `evaluate()` scans exactly
    # the one file it is given; it does no cross-module resolution. A guard that
    # imports an innocuous-looking `agentsec.*` helper which itself does `import
    # os` OUTSIDE `agentsec/guards/` or `agentsec/ai/` is invisible here by
    # design. Documented in `guard_sandbox.py`'s own module docstring ("the
    # deeper transitive closure ... is still out of scope") and
    # `docs/knowledge/guard-factory-and-sandbox-contract.md` ("Transitive
    # imports" under "What the contract does NOT cover"); also tracked as
    # decision C in the checklist-gap notes. Kept as a live regression
    # fixture (not xfail — this is expected, documented behavior, not a
    # surprise) so a future transitive-closure fix has a concrete case to flip.
    src = "from agentsec.utils_with_os import helper\nhelper()\n"
    assert evaluate("x.py", src) == []


def test_fuzz_getattr_builtins_eval_bypass() -> None:
    # FIXED: was a real bypass — the outer call's func is itself a
    # Call node (getattr(...)), which neither the bare-Name nor the clock-shaped
    # Attribute branch inspects, so the eval() invocation itself was never seen.
    # Closed at the source instead: `__builtins__` is now a banned bare Name
    # (_BANNED_NAMES) — a guard has no legitimate reason to reference it at all,
    # so the reflection is caught before getattr() even runs, regardless of what
    # attribute name is requested or whether the result is called immediately.
    src = "getattr(__builtins__, 'eval')('1 + 1')\n"
    violations = evaluate("x.py", src)
    assert any(v.kind == "name" and v.detail == "__builtins__" for v in violations)


def test_fuzz_globals_builtins_eval_bypass() -> None:
    # FIXED: same indirection class as the getattr bypass, via
    # globals()['__builtins__'].eval(...) instead — func is an Attribute whose
    # root is a Subscript, not a bare Name, so _attr_root() returned None and
    # the clock-call branch never matched. Closed by banning `globals` itself as
    # a call (_BANNED_CALLS) — a pure-function guard has no legitimate use for
    # process-namespace reflection, so the call is caught at `globals()`, before
    # the subscript/attribute chain that reaches eval is ever evaluated.
    src = "globals()['__builtins__'].eval('1 + 1')\n"
    violations = evaluate("x.py", src)
    assert any(v.kind == "call" and v.detail == "globals" for v in violations)


def test_fuzz_locals_and_vars_reflection_banned() -> None:
    # Same reflection family as globals() — banned alongside it (locals()
    # explicitly requested by the fix scope; vars() closes the identical
    # sibling bypass vars()['__builtins__'] before it's found the hard way,
    # since vars() with no arguments IS locals()).
    assert any(v.kind == "call" and v.detail == "locals" for v in evaluate("x.py", "locals()\n"))
    assert any(v.kind == "call" and v.detail == "vars" for v in evaluate("x.py", "vars()\n"))


def test_fuzz_sys_modules_indirect_os_access_bypass() -> None:
    # FIXED: `sys` was not on _BANNED_IMPORT_ROOTS (reasonable in
    # isolation), but `sys.modules['os']` reaches the live os module already
    # loaded into the audit process, and the resulting call's func is an
    # Attribute rooted in a Subscript — the same _attr_root() blind spot as the
    # globals() case, so neither the os access nor the os.system(...) call was
    # ever flagged. Closed at the import: `sys` now joins _BANNED_IMPORT_ROOTS,
    # since `sys.modules` alone is equivalent to importing anything already
    # loaded into the process — no legitimate guard needs it.
    src = "import sys\nsys.modules['os'].system('echo pwned')\n"
    violations = evaluate("x.py", src)
    assert any(v.kind == "import" and v.detail == "sys" for v in violations)


def test_fuzz_builtins_module_import_bypass() -> None:
    # #888 review, FIXED: the stdlib `builtins` module (distinct from the
    # `__builtins__` dunder) holds eval/exec/open/__import__/globals/…; reached via
    # `builtins.eval(...)` (an Attribute call, not a bare Name) it evaded
    # _BANNED_CALLS, and `builtins` was never on _BANNED_IMPORT_ROOTS — the exact
    # mirror of the `sys` gap. Closed by adding `builtins` to the import roots,
    # since importing it reaches the same capability as importing os by name.
    src = "import builtins\nbuiltins.eval('1 + 1')\n"
    violations = evaluate("x.py", src)
    assert any(v.kind == "import" and v.detail == "builtins" for v in violations)


def test_fuzz_builtins_module_aliased_import_bypass() -> None:
    # The aliased form is caught too — the import-root check resolves the real
    # module name (`builtins`), not the local alias.
    src = "import builtins as bi\nbi.open('/etc/passwd', 'w')\n"
    violations = evaluate("x.py", src)
    assert any(v.kind == "import" and v.detail == "builtins" for v in violations)


def test_fuzz_builtins_name_reference_without_call_still_flagged() -> None:
    # The name ban fires on the bare reference itself, not just when it's
    # immediately fed into getattr() — a guard has no legitimate reason to name
    # __builtins__ at all, called or not.
    assert any(v.kind == "name" and v.detail == "__builtins__"
               for v in evaluate("x.py", "x = __builtins__\n"))
