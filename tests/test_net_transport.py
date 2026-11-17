"""#976: the egress boundary's error contract, driven over real loopback sockets.

Every caller of `agentsec/net.py` catches a transport failure as an `OSError`, urllib's documented
failure set. `http.client` raises a truncated or malformed response as an `HTTPException`, which is
not an `OSError`, and `urllib.request.urlopen` does not wrap it. Before #976 that exception escaped
every caller documented as never raising (`fetch_kev`, `fetch_epss`, `check_updates`, the whole
`scan-live-url` surface), and the command died with a traceback and no report.

Every older test stubs `net._raw_request`, `net.urlopen` or an injected `fetch=`, which is how the
gap survived. These stub nothing: a one-shot raw socket server on 127.0.0.1 sends the malformed
bytes and the real boundary reads them. Both directions (CLAUDE.md Rule 1): each malformed shape
leaves as `net.ProtocolError`, while a well-formed 200, a refused connection, a close without a
response and a real 404 still pass through exactly as before.
"""
from __future__ import annotations

import http.client
import io
import re
import socket
import threading
import urllib.error
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentsec import deps_apply, deps_monitor, epss, kev, live, livescan, net, update_check
from agentsec.cli import main
from agentsec.runners import go_osv_hygiene

_HOST = "127.0.0.1"
_TIMEOUT = 5  # seconds, both ends; every exchange here takes milliseconds
_NOW = datetime(2026, 10, 6, tzinfo=UTC)
_CONTENT_LENGTH = re.compile(rb"(?im)^content-length:\s*(\d+)")

_OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]"
_NOT_FOUND = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


@dataclass(frozen=True)
class _Shape:
    """One malformed response, and the `http.client` exception it raises."""

    id: str
    payload: bytes
    raised: type[http.client.HTTPException]
    # Does a bounded `read(n)` raise too? Not on a short Content-Length body: CPython returns the
    # short data there ("would raise IncompleteRead ... but it might break compatibility").
    bounded_read_raises: bool = True


_SHAPES = [
    _Shape("incomplete-content-length", b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc",
           http.client.IncompleteRead, bounded_read_raises=False),
    _Shape("incomplete-chunked", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n64\r\nabc",
           http.client.IncompleteRead),
    _Shape("bad-status-line", b"garbage\r\n\r\n", http.client.BadStatusLine),
    _Shape("header-line-too-long", b"HTTP/1.1 200 OK\r\nX-Long: " + b"a" * 70_000 + b"\r\n\r\n",
           http.client.LineTooLong),
    _Shape("chunk-size-line-too-long",
           b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + b"1" * 70_000, http.client.LineTooLong),
]
_SHAPE = {s.id: s for s in _SHAPES}


@dataclass
class _Server:
    url: str
    requested: threading.Event = field(default_factory=threading.Event)


def _drain_request(conn: socket.socket) -> None:
    """Read one whole request (headers, then any Content-Length body). A server that answers or
    closes before the request is fully read makes the client see a reset, not the shape under test."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(65536)
        if not chunk:
            return
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    m = _CONTENT_LENGTH.search(head)
    left = (int(m.group(1)) if m else 0) - len(body)
    while left > 0:
        chunk = conn.recv(65536)
        if not chunk:
            return
        left -= len(chunk)


@pytest.fixture
def serve() -> Iterator[Callable[[bytes], _Server]]:
    """`serve(payload)` starts a one-shot raw socket server on loopback. It accepts one connection,
    reads the request, sends `payload` verbatim and closes, so the client sees exactly those bytes
    and then EOF. `requested` is set before the reply is sent, so it is always set by the time the
    client has read anything."""
    listeners: list[socket.socket] = []
    threads: list[threading.Thread] = []

    def start(payload: bytes) -> _Server:
        listener = socket.create_server((_HOST, 0))
        listener.settimeout(_TIMEOUT)
        listeners.append(listener)
        server = _Server(f"http://{_HOST}:{listener.getsockname()[1]}/")

        def run() -> None:
            try:
                conn, _ = listener.accept()
            except OSError:
                return  # nobody connected: the test failed before sending its request
            with conn:
                conn.settimeout(_TIMEOUT)
                try:
                    _drain_request(conn)
                    server.requested.set()
                    conn.sendall(payload)
                except OSError:
                    pass  # the client hung up mid-send: a LineTooLong stops reading at 64 KiB

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        threads.append(thread)
        return server

    yield start
    for listener in listeners:
        listener.close()
    for thread in threads:
        thread.join(timeout=_TIMEOUT)


def _get(url: str) -> bytes:
    return net.get(url, tier_required=1, sends="nothing", feature="test", tier=1, timeout=_TIMEOUT)


def _refused_url() -> str:
    """A loopback URL nothing listens on: bind an ephemeral port, then release it."""
    with socket.socket() as s:
        s.bind((_HOST, 0))
        port = s.getsockname()[1]
    return f"http://{_HOST}:{port}/"


# --- the boundary: every malformed shape leaves as net.ProtocolError --------------------------

@pytest.mark.parametrize("shape", [pytest.param(s, id=s.id) for s in _SHAPES])
def test_get_translates_a_malformed_response(serve: Callable[[bytes], _Server], shape: _Shape) -> None:
    with pytest.raises(net.ProtocolError) as exc:
        _get(serve(shape.payload).url)
    # A URLError, so an OSError: every caller's existing except tuple already catches it.
    assert isinstance(exc.value, urllib.error.URLError) and isinstance(exc.value, OSError)
    assert isinstance(exc.value.__cause__, shape.raised)
    assert shape.raised.__name__ in str(exc.value)


@pytest.mark.parametrize("shape", [pytest.param(s, id=s.id) for s in _SHAPES])
def test_urlopen_translates_a_malformed_response(serve: Callable[[bytes], _Server], shape: _Shape) -> None:
    """Header-phase shapes raise from `net.urlopen` itself; body-phase shapes raise from the
    caller's `read()`, which runs outside net.py and so needs the response wrapper."""
    url = serve(shape.payload).url
    with pytest.raises(net.ProtocolError) as exc, net.urlopen(url, timeout=_TIMEOUT) as resp:
        resp.read()
    assert isinstance(exc.value.__cause__, shape.raised)


@pytest.mark.parametrize("shape", [pytest.param(s, id=s.id) for s in _SHAPES if s.bounded_read_raises])
def test_urlopen_translates_a_malformed_response_on_a_bounded_read(
    serve: Callable[[bytes], _Server], shape: _Shape,
) -> None:
    url = serve(shape.payload).url
    with pytest.raises(net.ProtocolError) as exc, net.urlopen(url, timeout=_TIMEOUT) as resp:
        resp.read(4096)
    assert isinstance(exc.value.__cause__, shape.raised)


def test_a_non_numeric_port_is_translated_before_any_connection() -> None:
    """`InvalidURL` is the fourth `HTTPException` shape, and a fetched page can supply it."""
    with pytest.raises(net.ProtocolError) as exc:
        net.urlopen("http://127.0.0.1:abc/", timeout=_TIMEOUT)
    assert isinstance(exc.value.__cause__, http.client.InvalidURL)
    assert "invalid URL (InvalidURL)" in str(exc.value)
    with pytest.raises(net.ProtocolError):
        _get("http://127.0.0.1:abc/")


def test_the_message_names_the_class_and_never_echoes_server_text(serve: Callable[[bytes], _Server]) -> None:
    """`str(BadStatusLine)` is the raw status line the server chose (up to 64 KiB, any bytes), and
    callers interpolate the error into terminal-facing reasons."""
    marker = "SERVER-CHOSEN-TEXT"
    payload = b"garbage\x1b[31m" + marker.encode() * 1000 + b"\r\n\r\n"
    with pytest.raises(net.ProtocolError) as exc:
        _get(serve(payload).url)
    assert marker in str(exc.value.__cause__)  # the stdlib exception carries it ...
    for text in (str(exc.value), str(exc.value.reason)):
        assert "\x1b" not in text and marker not in text  # ... the translated one never does
        assert "malformed HTTP response (BadStatusLine)" in text


# --- the callers #976 names: each degrades the way its docstring promises ---------------------

def test_fetch_kev_degrades_to_the_empty_set(
    serve: Callable[[bytes], _Server], monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    server = serve(_SHAPE["bad-status-line"].payload)
    monkeypatch.setattr(kev, "KEV_URL", server.url)
    assert kev.fetch_kev(tier=1, now=_NOW, cache_dir=tmp_path) == set()
    assert server.requested.is_set()  # the real fetch ran
    assert not kev.cache_path(tmp_path).exists()  # and nothing was cached from it


def test_fetch_epss_degrades_to_the_cached_scores(
    serve: Callable[[bytes], _Server], monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    server = serve(_SHAPE["incomplete-chunked"].payload)
    monkeypatch.setattr(epss, "EPSS_URL", server.url)
    assert epss.fetch_epss({"CVE-2024-0001"}, tier=1, now=_NOW, cache_dir=tmp_path) == {}
    assert server.requested.is_set()


def test_check_updates_reports_the_error_instead_of_raising(
    serve: Callable[[bytes], _Server], monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    server = serve(_SHAPE["header-line-too-long"].payload)
    monkeypatch.setattr(update_check, "VERSIONS_URL", server.url)
    result = update_check.check_updates(tier=1, now=_NOW, cache_dir=tmp_path, refresh=True)
    assert result.remote_version is None
    assert result.error is not None and "LineTooLong" in result.error


@pytest.mark.parametrize("shape_id", ["incomplete-chunked", "bad-status-line"])
def test_the_ownership_gate_fails_closed_without_raising(
    serve: Callable[[bytes], _Server], shape_id: str,
) -> None:
    """The chunked shape is the one that raised even through the gate's bounded `read(4096)`."""
    result = livescan.verify_ownership_file(serve(_SHAPE[shape_id].payload).url, "tok", timeout=_TIMEOUT)
    assert result.verified is False and "malformed HTTP response" in result.reason


def test_a_page_controlled_script_port_skips_only_that_script(serve: Callable[[bytes], _Server]) -> None:
    """The `<script src>` comes from the fetched (untrusted) page. A non-numeric port in it raised
    `InvalidURL` out of a function documented as never raising; now that one script is skipped and
    the config the page itself serves is still found."""
    supabase_url = "https://abcdefgh.supabase.co"
    anon_key = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.c2lnbmF0dXJlLXNpZw"
    page = (
        '<html><script src="http://127.0.0.1:abc/a.js"></script>'
        f'<script>createClient("{supabase_url}", "{anon_key}")</script></html>'
    ).encode()
    payload = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(page) + page
    found = livescan.discover_supabase_config(serve(payload).url, timeout=_TIMEOUT)
    assert found == (supabase_url, anon_key)


def test_a_live_probe_skips_instead_of_raising(serve: Callable[[bytes], _Server]) -> None:
    result = livescan.probe_exposed_tables(
        serve(_SHAPE["incomplete-chunked"].payload).url, "anon", timeout=_TIMEOUT,
    )
    assert result.ran is False and "malformed HTTP response" in result.skip_reason


def test_the_splinter_fetch_reports_why_instead_of_raising(
    serve: Callable[[bytes], _Server], monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live, "SPLINTER_URL", serve(_SHAPE["incomplete-content-length"].payload).url)
    sql, err = live._resolve_splinter_sql(None, allow_fetch=True)
    assert sql is None and "malformed HTTP response (IncompleteRead)" in err


def test_reachable_is_false_on_header_garbage_and_true_on_a_truncated_body(
    serve: Callable[[bytes], _Server],
) -> None:
    """Its contract is "any HTTP status = reachable": a truncated body still came with a status,
    garbage did not."""
    assert live._reachable(serve(_SHAPE["bad-status-line"].payload).url, timeout=_TIMEOUT) is False
    assert live._reachable(serve(_SHAPE["incomplete-content-length"].payload).url, timeout=_TIMEOUT) is True


def test_deps_monitor_fetch_raises_a_transient_error_it_retries(serve: Callable[[bytes], _Server]) -> None:
    """Its `Fetch` protocol MUST raise; before #976 the raw `IncompleteRead` classified as a
    `defect` (no retry) and escaped the callers' `(OSError, ValueError)` tuples."""
    with pytest.raises((OSError, ValueError)) as exc:  # the callers' own tuple
        deps_monitor.default_fetch(serve(_SHAPE["incomplete-content-length"].payload).url)
    assert deps_apply.classify(exc.value) == (
        "transient", "network error (malformed HTTP response (IncompleteRead))",
    )


def test_the_go_osv_module_check_raises_what_its_runner_catches(
    serve: Callable[[bytes], _Server], monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The runner's tuples are `(URLError, TimeoutError, ...)` with no OSError rung, which is why
    the translation is a URLError and not a plain OSError: the module is "inconclusive" instead of
    the whole runner erroring."""
    url = serve(_SHAPE["bad-status-line"].payload).url
    monkeypatch.setattr(go_osv_hygiene, "_GO_PROXY_INFO_URL", url + "{module}/@v/{version}.info")
    with pytest.raises(urllib.error.URLError):
        go_osv_hygiene._module_resolves("example.com/m", "v1.0.0", tier=1)


def test_audit_kev_survives_a_malformed_kev_response_and_writes_its_report(
    serve: Callable[[bytes], _Server], monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """End to end (Rule 3: assert the artifact). Before #976 this raised out of `main` and wrote
    no report."""
    server = serve(_SHAPE["bad-status-line"].payload)
    monkeypatch.setattr(kev, "KEV_URL", server.url)
    home = tmp_path / "home"
    home.mkdir()
    # A fresh ~/.agentsec/kev-cache.json would short-circuit the fetch under test.
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("DO_NOT_TRACK", raising=False)
    monkeypatch.delenv("AGENTSEC_NETWORK", raising=False)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    out = tmp_path / "report.md"
    rc = main(["audit", str(repo), "--kev", "--network", "tier1", "--guards-only", "--no-fail",
               "--out", str(out)])
    assert rc == 0
    assert server.requested.is_set()  # the KEV fetch really ran: no cache hit, no tier refusal
    assert out.read_text(encoding="utf-8").strip()


# --- counterweights: what is not malformed passes through untouched ---------------------------

def test_a_well_formed_response_passes_through_byte_for_byte(serve: Callable[[bytes], _Server]) -> None:
    assert _get(serve(_OK).url) == b"[]"
    with net.urlopen(serve(_OK).url, timeout=_TIMEOUT) as resp:
        assert resp.read() == b"[]"
    with net.urlopen(serve(_OK).url, timeout=_TIMEOUT) as resp:
        assert resp.read(1) == b"[" and resp.read(1) == b"]"
        # Everything but read() forwards to the real response.
        assert resp.status == 200 and resp.getcode() == 200 and resp.headers["Content-Length"] == "2"


def test_only_read_is_translated_and_the_rest_of_the_surface_is_as_documented() -> None:
    """Pins the `_Response` surface its docstring states (PR #1026 review, M1): `readline()` and
    `readinto()` forward to the raw response untranslated, and iteration is unsupported, because
    Python looks `__iter__` up on the type and never through `__getattr__`. A method added to the
    wrapper changes this test and that docstring together."""
    resp = net._Response(io.BytesIO(b"a\nb\n"))
    assert resp.readline() == b"a\n"
    buf = bytearray(1)
    assert resp.readinto(buf) == 1 and buf == b"b"
    with pytest.raises(TypeError, match="not iterable"):
        iter(resp)


def test_a_refused_connection_is_not_rewritten() -> None:
    with pytest.raises(urllib.error.URLError) as exc:
        _get(_refused_url())
    assert type(exc.value) is urllib.error.URLError  # urllib's own wrapping, not a ProtocolError
    assert isinstance(exc.value.reason, OSError)


def test_close_without_a_response_stays_remote_disconnected(serve: Callable[[bytes], _Server]) -> None:
    """`RemoteDisconnected` is the one `HTTPException` that is already an `OSError` every caller
    handles, so the boundary re-raises it as is rather than translating it."""
    with pytest.raises(http.client.RemoteDisconnected):
        _get(serve(b"").url)
    with pytest.raises(http.client.RemoteDisconnected):
        net.urlopen(serve(b"").url, timeout=_TIMEOUT)


def test_an_http_error_status_is_not_rewritten(
    serve: Callable[[bytes], _Server], monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An `HTTPError` is not an `HTTPException`, and the callers that branch on it keep their meaning."""
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(serve(_NOT_FOUND).url)
    assert exc.value.code == 404
    exc.value.close()
    url = serve(_NOT_FOUND).url
    monkeypatch.setattr(go_osv_hygiene, "_GO_PROXY_INFO_URL", url + "{module}/@v/{version}.info")
    assert go_osv_hygiene._module_resolves("example.com/m", "v1.0.0", tier=1) is False  # 404: no such module
    assert live._reachable(serve(_NOT_FOUND).url, timeout=_TIMEOUT) is True  # any status: reachable
