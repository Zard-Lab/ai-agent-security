from __future__ import annotations

from agentsec.guards.no_pan_stored import NoPanStoredGuard
from tests.guards._common import *  # noqa: F401,F403


def test_no_pan_flags_card_number_field(tmp_path: Path) -> None:
    (tmp_path / "models.py").write_text("card_number = form['cc']\n", encoding="utf-8")
    findings = NoPanStoredGuard().run(tmp_path, _payprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "no-pan-stored/raw-card-data"
    assert findings[0].severity == "high"

def test_no_pan_flags_dict_index_assignment(tmp_path: Path) -> None:
    (tmp_path / "models.py").write_text('record["card_number"] = body["cc"]\n', encoding="utf-8")
    findings = NoPanStoredGuard().run(tmp_path, _payprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "no-pan-stored/raw-card-data"

def test_no_pan_not_tripped_by_equality_check_or_read(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text(
        "if card_number == expected:\n"
        "    pass\n"
        "elif record['card_number']:\n"
        "    pass\n", encoding="utf-8"
    )
    assert NoPanStoredGuard().run(tmp_path, _payprof(tmp_path)) == []

def test_no_pan_flags_cvv_logged(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text("logger.info(f'charging card {cvv}')\n", encoding="utf-8")
    assert len(NoPanStoredGuard().run(tmp_path, _payprof(tmp_path))) == 1

def test_no_pan_passes_last4_and_brand(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text(
        "card_last4 = token.card.last4\n"
        "brand = token.card.brand\n"
        "exp_month = token.card.exp_month\n", encoding="utf-8"
    )
    assert NoPanStoredGuard().run(tmp_path, _payprof(tmp_path)) == []

def test_no_pan_not_tripped_by_similar_names(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text("scorecard_number = 7\ndiscard_number = 5\n", encoding="utf-8")
    assert NoPanStoredGuard().run(tmp_path, _payprof(tmp_path)) == []

def test_no_pan_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text("card_number = token.card.last4  # security: allow-card-field\n", encoding="utf-8")
    assert NoPanStoredGuard().run(tmp_path, _payprof(tmp_path)) == []

def test_no_pan_logged_field_name_in_message_string_silent(tmp_path: Path) -> None:
    # FP-bait (#424): a card field NAME inside a log MESSAGE string is prose, not a logged value.
    (tmp_path / "m.py").write_text(
        "import logging\nlogger = logging.getLogger(__name__)\n"
        'logger.info("card_number field removed from schema")\n',
        encoding="utf-8",
    )
    assert NoPanStoredGuard().run(tmp_path, _payprof(tmp_path)) == []

def test_no_pan_still_flags_logged_card_variable(tmp_path: Path) -> None:
    # The single-line-string masking must NOT suppress a real logged card VALUE (bare identifier).
    (tmp_path / "m.py").write_text(
        "import logging\nlogger = logging.getLogger(__name__)\n"
        "logger.info(card_number)\n",
        encoding="utf-8",
    )
    assert len(NoPanStoredGuard().run(tmp_path, _payprof(tmp_path))) == 1

def test_no_pan_silent_on_docstring_example(tmp_path: Path) -> None:
    # FP-bait (#424): the module docstring names `card_number` next to the word "log"; a
    # docstring example must not self-match (strip_python_strings blanks it).
    (tmp_path / "m.py").write_text(
        '"""Never log a card_number or cvv value."""\n'
        "x = 1\n",
        encoding="utf-8",
    )
    assert NoPanStoredGuard().run(tmp_path, _payprof(tmp_path)) == []

def test_no_pan_na_without_payments() -> None:
    assert NoPanStoredGuard().applies(mkprofile(Path("/tmp"), features={"python"})) is False



def test_no_pan_stored_flags_string_keyed_index_read(tmp_path: Path) -> None:
    # Regression (#439 review): `_code_view` deleted ALL string literals before the LOGGED
    # check, so a PAN/CVV read through a string-keyed index — the commonest real leak shape
    # — was erased along with the prose it was meant to remove. Each of these previously
    # produced a finding and produced none after the change.
    (tmp_path / "a.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        'logger.info(data["card_number"])\n'
        'logger.info(payload["cvv"])\n'
        'logger.info("ctx %s", row["card_number"])\n',
        encoding="utf-8",
    )
    findings = NoPanStoredGuard().run(tmp_path, _payprof(tmp_path))
    assert len(findings) == 3


def test_no_pan_stored_silent_on_field_name_in_prose(tmp_path: Path) -> None:
    # FP-bait for the above, and the reason `_code_view` exists: naming the field in a log
    # MESSAGE is not logging its value. A subscript key is a read; prose is not.
    (tmp_path / "a.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        'logger.info("card_number removed from payload")\n'
        'logger.info("we never store cvv")\n',
        encoding="utf-8",
    )
    assert NoPanStoredGuard().run(tmp_path, _payprof(tmp_path)) == []


def test_no_pan_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string on the flagged line is not a comment; neutral run = control.
    for note in ("# reviewed", "# security: allow-card-field"):
        (tmp_path / "m.py").write_text(f'card_number = form.card_number; _note = "{note}"\n', encoding="utf-8")
        findings = NoPanStoredGuard().run(tmp_path, _payprof(tmp_path))
        assert [f.rule for f in findings] == ["no-pan-stored/raw-card-data"], note
