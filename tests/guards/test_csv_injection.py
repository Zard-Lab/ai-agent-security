from __future__ import annotations

import time

import pytest

from agentsec.guards.csv_injection import CsvInjectionGuard
from tests._timing import assert_growth
from tests.guards._common import *  # noqa: F401,F403


def test_csv_openpyxl_no_safe_cell(tmp_path: Path) -> None:
    (tmp_path / "export.py").write_text(
        "import openpyxl\n"
        "wb = openpyxl.Workbook()\n"
        "ws = wb.active\n"
        "ws.cell(row=1, column=1, value=user_input)\n", encoding="utf-8"
    )
    findings = CsvInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "csv-injection/unsafe-cell-write"
    assert findings[0].severity == "medium"

def test_csv_writer_no_safe_cell(tmp_path: Path) -> None:
    (tmp_path / "report.py").write_text(
        "import csv\n"
        "with open('out.csv', 'w') as f:\n"
        "    writer = csv.writer(f)\n"
        "    writer.writerow([name, amount, notes])\n", encoding="utf-8"
    )
    findings = CsvInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "csv-injection/unsafe-cell-write" for f in findings)

def test_csv_passes_when_safe_cell_defined(tmp_path: Path) -> None:
    (tmp_path / "utils.py").write_text(
        "def safe_cell(value: str) -> str:\n"
        "    if value and value[0] in ('=', '+', '-', '@'):\n"
        "        return \"'\" + value\n"
        "    return value\n", encoding="utf-8"
    )
    (tmp_path / "export.py").write_text(
        "import openpyxl\n"
        "from utils import safe_cell\n"
        "ws.cell(row=1, column=1, value=safe_cell(user_input))\n", encoding="utf-8"
    )
    assert CsvInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_csv_passes_with_prefixed_sanitizer_name(tmp_path: Path) -> None:
    # T1d precision: a prefixed/qualified sanitizer (`_safe_csv_cell`) is recognized too — the bare
    # `safe_cell` regex was a false positive on the flagship's `_safe_csv_cell` helper.
    (tmp_path / "audit_log.py").write_text(
        "import csv\n"
        "def _safe_csv_cell(v):\n"
        "    return \"'\" + v if v and v[0] in '=+-@' else v\n"
        "def export(rows, w):\n"
        "    for r in rows:\n"
        "        w.writerow({k: _safe_csv_cell(v) for k, v in r.items()})\n",
        encoding="utf-8",
    )
    assert CsvInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_csv_passes_with_pragma(tmp_path: Path) -> None:
    (tmp_path / "export.py").write_text(
        "import csv\n"
        "writer.writerow([row])  # security: allow-formula-output\n", encoding="utf-8"
    )
    assert CsvInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_csv_no_import_silent(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n", encoding="utf-8"
    )
    assert CsvInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_csv_many_writes_one_file_one_finding(tmp_path: Path) -> None:
    # The primary precision fix: a file with N write calls emits exactly 1 finding,
    # not N findings. The message includes a count of suppressed additional occurrences.
    lines = ["import csv\n"] + [f"writer.writerow([row{i}])\n" for i in range(10)]
    (tmp_path / "export.py").write_text("".join(lines), encoding="utf-8")
    findings = CsvInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert "9 more" in findings[0].message

def test_csv_multiple_files_each_get_one_finding(tmp_path: Path) -> None:
    # Two files with write calls → 2 findings (one per file), not N per write call.
    (tmp_path / "export_a.py").write_text(
        "import csv\nwriter.writerow([a])\nwriter.writerow([b])\n", encoding="utf-8"
    )
    (tmp_path / "export_b.py").write_text(
        "import openpyxl\nws.cell(row=1, column=1)\nws.cell(row=2, column=1)\n", encoding="utf-8"
    )
    findings = CsvInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 2

def test_csv_openpyxl_read_code_silent(tmp_path: Path) -> None:
    # #423 FP-bait: openpyxl/csv READ code — a cell-value read, a plain list build, and a
    # subscript read — must not fire (they are not writes).
    (tmp_path / "reader.py").write_text(
        "import openpyxl\n"
        "wb = openpyxl.load_workbook('in.xlsx')\n"
        "ws = wb.active\n"
        "rows = []\n"
        "for r in range(1, 10):\n"
        "    val = ws.cell(row=r, column=1).value\n"
        "    header = ws['A1'].value\n"
        "    rows.append([val, header])\n",
        encoding="utf-8",
    )
    assert CsvInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

@pytest.mark.parametrize("receiver", [
    # Last segment STARTS with ws / sheet / worksheet.
    "ws", "ws1", "ws_out", "ws_index", "ws_headers", "WS", "self.ws",
    "sheet", "Sheet", "sheet1", "sheet_1", "sheet_out", "sheet_data",
    "worksheet", "WORKSHEET", "worksheet_1",
    # `.active` owned by a workbook-ish segment.
    "wb.active", "workbook.active", "self.wb.active", "my_wb.active",
    "_wb.active", "_workbook.active", "self._wb.active",
])
def test_csv_ws_append_still_fires_across_receiver_spellings(
    tmp_path: Path, receiver: str
) -> None:
    # STILL-FIRES for the direction the `.append([...])` receiver rule traded against. Every
    # receiver here is a real write of a list literal into a worksheet.
    (tmp_path / "export.py").write_text(
        "import openpyxl\n"
        "wb = openpyxl.Workbook()\n"
        f"{receiver}.append([user_input, note])\n",
        encoding="utf-8",
    )
    findings = CsvInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "csv-injection/unsafe-cell-write"


@pytest.mark.parametrize("receiver", [
    # Ordinary list builds. `rows` is load-bearing: it ENDS in "ws", so an unanchored receiver
    # rule re-opens the exact false positive this arm exists to close.
    "rows", "records", "matrix", "out", "windows", "flows", "news", "workspaces", "active_users",
    # `.active` on an owner that is not a workbook. A leading dot distinguishes an attribute from
    # a local; it says nothing about who owns the attribute.
    "active", "self.active", "queue.active", "obj.objects.active",
    "notebook.active", "facebook.active", "order_book.active", "book.active",
    # Identifiers CONTAINING "sheet" without starting with it. A substring rule (`\w*sheet\w*`)
    # fired on every one of these (#452 re-gate).
    "timesheet_entries", "balance_sheet_rows", "spreadsheet_names", "stylesheet_urls",
    "cheatsheet_rows", "datasheet_specs", "timesheet", "cheatsheet", "spreadsheet",
    "balance_sheet", "cover_sheet",
])
def test_csv_plain_list_append_stays_silent(tmp_path: Path, receiver: str) -> None:
    # FP-BAIT for the receiver rule. NOTE, because this went wrong twice: a bait case only counts
    # if it can actually REACH the arm it defends. An earlier version parametrized five receivers
    # of which none contained "sheet" and none had a leading dot, so not one could reach the
    # `.active` arm under any spelling. Check new entries against the rule before adding them.
    (tmp_path / "build.py").write_text(
        "import openpyxl\n"
        "wb = openpyxl.Workbook()\n"
        f"{receiver} = []\n"
        f"{receiver}.append([val, header])\n",
        encoding="utf-8",
    )
    assert CsvInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []


@pytest.mark.parametrize(("receiver", "fires"), [
    # FALSE POSITIVES we accept: collections named after sheets, and the `ws` WebSocket collision.
    ("sheet_names", True), ("sheet_titles", True), ("sheets", True), ("worksheets", True),
    ("ws_messages", True), ("wsgi_rows", True),
    # FALSE NEGATIVES we accept: `sheet` not in prefix position, camelCase, ambiguous shorthands.
    ("output_sheet", False), ("data_sheet", False), ("dataSheet", False), ("mySheet", False),
    ("tab", False), ("sh", False),
])
def test_csv_append_documented_residuals(tmp_path: Path, receiver: str, fires: bool) -> None:
    """Pins the receiver rule's KNOWN wrong answers, so changing one is a deliberate act.

    Three progressively cleverer rules were tried across #452 and each shipped green and was
    measured wrong in a new direction the round after. The arm is now a one-sentence prefix test
    with its error set enumerated here rather than discovered by the next reviewer. Closing these
    is follow-up work with a corpus behind it; if a change flips one of these, that is the signal
    to go read that issue, not to adjust this list.
    """
    (tmp_path / "x.py").write_text(
        "import openpyxl\n"
        "wb = openpyxl.Workbook()\n"
        f"{receiver}.append([a, b])\n",
        encoding="utf-8",
    )
    findings = CsvInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert bool(findings) is fires


def test_csv_append_scan_is_linear_in_line_length() -> None:
    # `_APPEND_CALL` has no literal prefix, so without the `(?<![\w.])` anchor the engine
    # re-expands `[\w.]+` from every position inside an unbroken run of word characters. A single
    # 40k-character token (an embedded blob, a base64 test vector) cost ~6 SECONDS in this one arm
    # (#452 re-gate round 2). Quadratic growth would blow this budget by orders of magnitude;
    # the threshold is loose on purpose so the test measures the COMPLEXITY, not the machine.
    from agentsec.guards.csv_injection import _is_write_call
    line = "x = '" + "a" * 40_000 + "'"
    start = time.perf_counter()
    assert _is_write_call(line) is False
    assert time.perf_counter() - start < 1.0


def test_csv_read_only_module_with_sheetish_list_is_silent(tmp_path: Path) -> None:
    # The end-to-end shape of the round-1 regression: a module that only READS csv, builds a list
    # named after a balance sheet, and contains no write anywhere. A substring receiver rule
    # emitted a MEDIUM "spreadsheet write" on it (#452 re-gate, measured 0 -> 1 -> 0).
    (tmp_path / "load.py").write_text(
        "import csv\n"
        "def load(fh):\n"
        "    balance_sheet_rows = []\n"
        "    for row in csv.reader(fh):\n"
        "        balance_sheet_rows.append([row[0], row[1]])\n"
        "    return balance_sheet_rows\n",
        encoding="utf-8",
    )
    assert CsvInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_csv_ws_subscript_assign_still_fires(tmp_path: Path) -> None:
    # STILL-FIRES for the `_WS_ASSIGN` narrowing (#452 review, Medium 3). The arm was narrowed
    # from a bare `ws\s*\[` to assignment-only so `x = ws['A1'].value` stops firing; nothing
    # asserted that the assignment itself — the actual write — survived that trade.
    (tmp_path / "export.py").write_text(
        "import openpyxl\n"
        "wb = openpyxl.Workbook()\n"
        "ws['A1'] = user_input\n"
        "ws['A2'].value = note\n",
        encoding="utf-8",
    )
    findings = CsvInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "csv-injection/unsafe-cell-write"


def test_csv_cell_value_comparison_is_read_not_write(tmp_path: Path) -> None:
    # PR #452 review: `ws.cell(...).value == x` is a read-COMPARISON, not an assignment —
    # the `(?!\s*=(?!=))` lookahead must not treat the `==` as a write.
    (tmp_path / "check.py").write_text(
        "import openpyxl\n"
        "def verify(ws, expected):\n"
        "    return ws.cell(row=1, column=1).value == expected\n",
        encoding="utf-8",
    )
    assert CsvInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []



def test_csv_cell_that_is_both_read_and_write_counts_as_a_write(tmp_path: Path) -> None:
    # Regression (#452 review): `_is_write_call` returned False for a line containing a
    # `.cell(...).value` READ, so an openpyxl sheet-to-sheet copy — which is both a read and a
    # write on one line — was missed. That is exactly the case this guard exists for: copying
    # untrusted cells into a new sheet.
    (tmp_path / "c.py").write_text(
        "import openpyxl\n"
        "def copy(src, dst):\n"
        "    for r in range(1, 10):\n"
        "        for c in range(1, 5):\n"
        "            dst.cell(row=r, column=c).value = src.cell(row=r, column=c).value\n",
        encoding="utf-8",
    )
    assert len(CsvInjectionGuard().run(tmp_path, _pyprof(tmp_path))) == 1


def test_csv_pure_cell_read_is_not_a_write(tmp_path: Path) -> None:
    # FP-bait: reading a cell (including a `==` comparison) is not writing one.
    (tmp_path / "c.py").write_text(
        "import openpyxl\n"
        "def read(ws):\n"
        "    x = ws.cell(row=1, column=1).value\n"
        "    if ws.cell(row=2, column=1).value == x:\n"
        "        return x\n",
        encoding="utf-8",
    )
    assert CsvInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []


# ---------------------------------------------------------------------------
# #697: the import gate must not rescan a blank-line run quadratically
#
# `_CSV_IMPORT` / `_OPENPYXL_IMPORT` run against WHOLE-file text on EVERY .py file in the repo, so
# a single generated file with trailing blank padding used to cost the whole guard quadratic time
# (measured 13.6s at 32,000 blank lines before the anchor conversion). Growth CLASS is the
# assertion, not wall clock: the constant is machine-dependent, the exponent is not.
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_csv_injection_blank_line_run_stays_linear(tmp_path: Path) -> None:
    # Four sizes, not three: `classify`'s median only discards an outlier from THREE ratios up
    # (at two it is their mean, which is #758). The fourth size extends the TOP, where this
    # workload is cheap enough that the extra step costs single-digit milliseconds.
    sizes = [2000, 8000, 32000, 128000]
    roots = {}
    for n in sizes:
        root = tmp_path / f"n{n}"
        root.mkdir()
        # A generated file with trailing blank padding, and NO csv/openpyxl import. The absence of
        # a match is the point: a matching line whose pattern ends in `\s*$` would swallow the run
        # into one match and hide the blow-up entirely (#697).
        (root / "generated_pb2.py").write_text("# @generated\nimport os\n" + "\n" * n, encoding="utf-8")
        # ...plus a real violation, so a guard that stopped matching cannot pass as "fast".
        (root / "export.py").write_text(
            "import csv\nw = csv.writer(f)\nw.writerow([user_input])\n", encoding="utf-8"
        )
        roots[n] = root

    found: dict[int, list[str]] = {}

    def scan(n: int) -> None:
        found[n] = [f.rule for f in CsvInjectionGuard().run(roots[n], _pyprof(roots[n]))]

    assert_growth(scan, sizes, expected="linear")
    assert all(found[n] == ["csv-injection/unsafe-cell-write"] for n in sizes), found


def test_csv_injection_still_detects_an_indented_import(tmp_path: Path) -> None:
    """Rule 1, the direction the anchor conversion traded against: `[^\\S\\n]*` still accepts
    same-line indentation (a conditional or in-function import), it only stops crossing lines."""
    (tmp_path / "export.py").write_text(
        "def build(f, rows):\n"
        "    import csv\n"
        "    w = csv.writer(f)\n"
        "    w.writerow(rows)\n",
        encoding="utf-8",
    )
    findings = CsvInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["csv-injection/unsafe-cell-write"]


def test_csv_injection_detects_an_import_after_a_blank_run(tmp_path: Path) -> None:
    """The blank run itself must not shadow a real import that follows it."""
    (tmp_path / "export.py").write_text(
        "# header\n" + "\n" * 50 + "import csv\nw = csv.writer(f)\nw.writerow(rows)\n",
        encoding="utf-8",
    )
    findings = CsvInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["csv-injection/unsafe-cell-write"]


def test_csv_injection_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma phrase inside a string on the write line is not a comment, so it must not suppress.
    for note in ("# security: allow-formula-output", "# neutral note"):
        (tmp_path / "export.py").write_text(
            "import csv\n"
            f'writer.writerow([row]); _note = "{note}"\n', encoding="utf-8"
        )
        findings = CsvInjectionGuard().run(tmp_path, _pyprof(tmp_path))
        assert [f.rule for f in findings] == ["csv-injection/unsafe-cell-write"], note
        assert findings[0].location.endswith("export.py:2")
