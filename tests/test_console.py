"""Tests for `agentsec.console.force_utf8_stdio` — the stdout/stderr half of the UTF-8 rule.

The function's whole contract is "reconfigure both streams to UTF-8, and never raise doing it",
so every test here is about a failure mode rather than a happy path: a stream that has no
`reconfigure` (a test double or a non-TextIOWrapper substitute), and one that raises because it
is detached or closed. A regression that turned this into a silent no-op would otherwise pass the
whole suite — nothing else exercises it (#453 re-gate).
"""
from __future__ import annotations

import sys
from typing import Any

import pytest

from agentsec.console import force_utf8_stdio


class _Recorder:
    """A stdout/stderr double that records the `reconfigure` calls it receives."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def reconfigure(self, **kwargs: Any) -> None:
        self.calls.append(kwargs)


class _Raiser:
    """A stream whose `reconfigure` raises — a detached or closed stream."""

    def __init__(self, exc: BaseException) -> None:
        self.exc = exc

    def reconfigure(self, **kwargs: Any) -> None:
        raise self.exc


class _NoReconfigure:
    """A stream substitute with no `reconfigure` at all (e.g. pytest's capture object)."""


def test_reconfigures_both_streams_to_utf8(monkeypatch: pytest.MonkeyPatch) -> None:
    out, err = _Recorder(), _Recorder()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    force_utf8_stdio()
    # BOTH streams, not just stdout — a `→` on stderr crashes a cp1252 console identically.
    assert out.calls == [{"encoding": "utf-8"}]
    assert err.calls == [{"encoding": "utf-8"}]


def test_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    # An entry point that calls it and then invokes another that also calls it must be fine.
    out, err = _Recorder(), _Recorder()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    force_utf8_stdio()
    force_utf8_stdio()
    assert out.calls == [{"encoding": "utf-8"}] * 2
    assert err.calls == [{"encoding": "utf-8"}] * 2


@pytest.mark.parametrize("exc", [OSError("detached"), ValueError("closed")])
def test_swallows_a_stream_that_cannot_be_reconfigured(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    # A detached/closed stream must not take the process down: this runs at entry-point start,
    # so raising here would turn a cosmetic encoding concern into a hard startup failure.
    monkeypatch.setattr(sys, "stdout", _Raiser(exc))
    monkeypatch.setattr(sys, "stderr", _Raiser(exc))
    force_utf8_stdio()  # must not raise


def test_a_failing_stdout_does_not_skip_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    # The suppression is per stream, not around the loop — a detached stdout must not cost
    # stderr its reconfigure (which is where a traceback lands).
    err = _Recorder()
    monkeypatch.setattr(sys, "stdout", _Raiser(OSError("detached")))
    monkeypatch.setattr(sys, "stderr", err)
    force_utf8_stdio()
    assert err.calls == [{"encoding": "utf-8"}]


def test_stream_without_reconfigure_is_a_no_op(monkeypatch: pytest.MonkeyPatch) -> None:
    # pytest's own capture replaces sys.stdout with an object that may lack `reconfigure`;
    # an AttributeError here would fail every test in the suite that captures output.
    monkeypatch.setattr(sys, "stdout", _NoReconfigure())
    monkeypatch.setattr(sys, "stderr", _NoReconfigure())
    force_utf8_stdio()  # must not raise


def test_the_arrow_is_why_this_exists() -> None:
    # The concrete regression (#453): `→` has no cp1252 code point, so a Windows console or a
    # redirected stdout kills the process on output it produced correctly. Pinning the premise
    # means a future "is this still needed?" is answered by the suite, not by memory.
    with pytest.raises(UnicodeEncodeError):
        "→".encode("cp1252")
    # ...while the ASCII replacement the script now prints is safe.
    assert "->".encode("cp1252") == b"->"
