from __future__ import annotations

import pytest

from agentsec.guards.upload_no_size_limit import UploadNoSizeLimitGuard
from tests.guards._common import *  # noqa: F401,F403


def test_upload_no_size_limit_fires(tmp_path: Path) -> None:
    (tmp_path / "upload.py").write_text(
        "from fastapi import UploadFile\n\nasync def save(file: UploadFile) -> None:\n    data = await file.read()\n",
        encoding="utf-8",
    )
    findings = UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert any(f.rule == "upload-no-size-limit/no-size-check" for f in findings)

def test_upload_no_size_limit_size_check_silences(tmp_path: Path) -> None:
    (tmp_path / "upload.py").write_text(
        "from fastapi import UploadFile\n\nasync def save(file: UploadFile) -> None:\n"
        "    max_size = 10 * 1024 * 1024\n    data = await file.read()\n",
        encoding="utf-8",
    )
    assert UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_upload_no_size_limit_read_upload_with_limit_silent(tmp_path: Path) -> None:
    # FP fix: read_upload_with_limit() is a recognised size-enforcement helper.
    (tmp_path / "upload.py").write_text(
        "from fastapi import UploadFile\n"
        "from utils import read_upload_with_limit\n\n"
        "async def ingest(file: UploadFile) -> None:\n"
        "    data = await read_upload_with_limit(file, 10 * 1024 * 1024)\n",
        encoding="utf-8",
    )
    assert UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

@pytest.mark.parametrize(
    "mention",
    [
        "from starlette.middleware.limit import ContentSizeLimitMiddleware\n",
        "# TODO ContentSizeLimitMiddleware\n",
        "if settings.LIMIT:\n    app.add_middleware(ContentSizeLimitMiddleware)\n",
    ],
    ids=["import", "comment", "under-if"],
)
def test_upload_no_size_limit_same_file_size_middleware_mention_still_fires(
    tmp_path: Path, mention: str
) -> None:
    # #472 WIDENING. The import case used to assert silence: the guard matched the middleware's
    # name anywhere in the file's raw text, so a bare import or a comment silenced every route in
    # the file. Neither limits anything; only an unconditional registration does.
    (tmp_path / "upload.py").write_text(
        "from fastapi import UploadFile\n" + mention + "\n"
        "async def ingest(file: UploadFile) -> None:\n"
        "    data = await file.read()\n",
        encoding="utf-8",
    )
    findings = UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert len(findings) == 1 and findings[0].rule == "upload-no-size-limit/no-size-check"


def test_upload_no_size_limit_content_size_middleware_registered_same_file_silent(tmp_path: Path) -> None:
    # FP-bait pair for the widening above: the middleware REGISTERED in the route's own file still
    # covers it, as the raw-text match did.
    (tmp_path / "upload.py").write_text(
        "from fastapi import FastAPI, UploadFile\n"
        "from starlette.middleware.limit import ContentSizeLimitMiddleware\n\n"
        "app = FastAPI()\n"
        "app.add_middleware(ContentSizeLimitMiddleware, max_content_size=10_000_000)\n\n"
        "@app.post('/upload')\n"
        "async def ingest(file: UploadFile) -> None:\n"
        "    data = await file.read()\n",
        encoding="utf-8",
    )
    assert UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []


@pytest.mark.parametrize(
    "registration",
    [
        "app.add_middleware(middleware_class=ContentSizeLimitMiddleware, max_content_size=10_000_000)\n",
        "asgi = ContentSizeLimitMiddleware(app, max_content_size=10_000_000)\n",
    ],
    ids=["keyword-middleware-class", "asgi-wrap"],
)
def test_upload_no_size_limit_keyword_and_asgi_wrap_registration_same_file_silent(
    tmp_path: Path, registration: str
) -> None:
    # #1016 review M1. The raw-text match silenced both forms before #472; the first version of
    # the AST pass read neither, so a correctly capped app fired again.
    (tmp_path / "upload.py").write_text(
        "from fastapi import FastAPI, UploadFile\n"
        "from app_middleware import ContentSizeLimitMiddleware\n\n"
        "app = FastAPI()\n" + registration + "\n"
        "@app.post('/upload')\n"
        "async def ingest(file: UploadFile) -> None:\n"
        "    data = await file.read()\n",
        encoding="utf-8",
    )
    assert UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_upload_no_size_limit_size_bytes_read_buffer_still_fires(tmp_path: Path) -> None:
    # Regression (PR #327 review): a `size_bytes`-named var used only as a streaming-read
    # chunk argument (no comparison, no enforced cap) must still fire — the naming-convention
    # match is anchored to a `max_`-prefixed name or a comparison context, not a bare substring.
    (tmp_path / "upload.py").write_text(
        "from fastapi import UploadFile\n\n"
        "async def ingest(file: UploadFile) -> None:\n"
        "    chunk_size_bytes = 8192\n"
        "    buf = b''\n"
        "    while True:\n"
        "        chunk = await file.read(chunk_size_bytes)\n"
        "        if not chunk:\n"
        "            break\n"
        "        buf += chunk\n",
        encoding="utf-8",
    )
    findings = UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert any(f.rule == "upload-no-size-limit/no-size-check" for f in findings)

def test_upload_no_size_limit_size_bytes_custom_helper_known_accepted_gap(tmp_path: Path) -> None:
    # KNOWN ACCEPTED FALSE-POSITIVE GAP (PR #327 round-2 review): anchoring `size_bytes` to a
    # `max_`-prefix or a comparison context (to close the chunk_size_bytes false negative above)
    # means a `size_bytes`-named variable passed to a CUSTOM-named helper with no inline
    # comparison no longer silences the guard, even when that helper enforces a real cap
    # internally. This is the same "guard can't see into a differently-named helper" limitation
    # already accepted for any size-check helper outside the 5-name hardcoded list
    # (upload_with_limit/read_upload_with_limit/read_with_limit/limit_upload/max_upload). This
    # test pins the current (accepted) behavior so a future regex edit doesn't silently change
    # it without the change being visible in a test diff.
    (tmp_path / "upload.py").write_text(
        "from fastapi import UploadFile\n"
        "from utils import validate_upload_size\n\n"
        "async def upload(file: UploadFile) -> None:\n"
        "    data = await file.read()\n"
        "    size_bytes = len(data)\n"
        "    validate_upload_size(size_bytes)\n",
        encoding="utf-8",
    )
    findings = UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert any(f.rule == "upload-no-size-limit/no-size-check" for f in findings)

def test_upload_no_size_limit_size_bytes_constant_and_comparison_silent(tmp_path: Path) -> None:
    # The size_bytes naming convention itself (issue #324's own suggested SIZE_BYTES form)
    # still silences the guard when actually used as a cap: either a MAX_*_SIZE_BYTES
    # constant name, or a direct comparison against a size_bytes-named variable.
    (tmp_path / "upload.py").write_text(
        "from fastapi import UploadFile\n\n"
        "MAX_UPLOAD_SIZE_BYTES = 5 * 1024 * 1024\n\n"
        "async def ingest(file: UploadFile) -> None:\n"
        "    uploaded_size_bytes = 0\n"
        "    data = await file.read()\n"
        "    uploaded_size_bytes = len(data)\n"
        "    if uploaded_size_bytes > MAX_UPLOAD_SIZE_BYTES:\n"
        "        raise HTTPException(status_code=413, detail='too large')\n",
        encoding="utf-8",
    )
    assert UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_upload_no_size_limit_unrelated_max_size_name_known_accepted_gap(tmp_path: Path) -> None:
    # KNOWN ACCEPTED HEURISTIC GAP (PR #327 review, issue #324): the MAX_<name>_SIZE
    # naming-convention match cannot lexically distinguish a real byte-size cap from an
    # unrelated max_*_size constant (pixel dimensions, pagination, ...). This test pins
    # the current, accepted behavior so a future regex edit doesn't silently widen or
    # narrow it without the change being visible in a test diff. NOT a bug: tightening
    # this would reopen the MAX_AVATAR_SIZE gap this guard exists to catch (issue #324),
    # since "AVATAR" and "IMAGE"/"PAGE" are lexically indistinguishable.
    (tmp_path / "upload.py").write_text(
        "from fastapi import UploadFile\n\n"
        "max_image_size = (1024, 1024)  # pixel dimensions for a resize step, NOT a byte cap\n\n"
        "async def upload_avatar(file: UploadFile) -> None:\n"
        "    data = await file.read()\n"
        "    resized = resize(data, max_image_size)\n",
        encoding="utf-8",
    )
    assert UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_upload_no_size_limit_project_named_max_size_constant_silent(tmp_path: Path) -> None:
    # Regression (issue #324): a MAX_<name>_SIZE-style constant (e.g. MAX_AVATAR_SIZE) doesn't
    # contain the literal substring "max_size" and was previously missed.
    (tmp_path / "upload.py").write_text(
        "from fastapi import UploadFile\n\n"
        "MAX_AVATAR_SIZE = 5 * 1024 * 1024\n\n"
        "async def upload_avatar(file: UploadFile) -> None:\n"
        "    file_content = b''\n"
        "    while True:\n"
        "        chunk = await file.read(1024 * 1024)\n"
        "        if not chunk:\n"
        "            break\n"
        "        file_content += chunk\n"
        "        if len(file_content) > MAX_AVATAR_SIZE:\n"
        "            raise HTTPException(status_code=413, detail='too large')\n",
        encoding="utf-8",
    )
    assert UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_upload_no_size_limit_size_check_in_following_function_still_fires(tmp_path: Path) -> None:
    # #423: a size check in a DIFFERENT (following) function must NOT suppress an unguarded
    # UploadFile route — the fixed 30-line window used to bleed across the boundary.
    (tmp_path / "upload.py").write_text(
        "from fastapi import UploadFile\n\n"
        "async def upload_avatar(file: UploadFile) -> None:\n"
        "    data = await file.read()\n"
        "    save(data)\n\n"
        "async def other(file2: UploadFile) -> None:\n"
        "    if len(await file2.read()) > max_size:\n"
        "        raise ValueError()\n",
        encoding="utf-8",
    )
    findings = UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    # upload_avatar (no size check) fires; `other` (has max_size) does not.
    assert len(findings) == 1
    assert findings[0].location.endswith(":3")

def test_upload_no_size_limit_inner_helper_does_not_fire_when_route_caps(tmp_path: Path) -> None:
    # Regression (#452 re-review, HIGH): `iter_functions` was widened to emit nested defs as
    # their own block. That is safe for the six DECORATOR-gated consumers, but this guard gates
    # on a `: UploadFile` PARAMETER ANNOTATION — and an inner helper that merely RECEIVES the
    # route's UploadFile carries that annotation too, without the route's cap in its own block.
    # A route that correctly enforces the cap was therefore reported on its private closure.
    (tmp_path / "upload.py").write_text(
        "from fastapi import FastAPI, HTTPException, UploadFile\n\n"
        "app = FastAPI()\n\n"
        "@app.post('/upload')\n"
        "async def upload_endpoint(file: UploadFile):\n"
        "    MAX_FILE_SIZE = 1_000_000\n"
        "    async def _read_capped(f: UploadFile) -> bytes:\n"
        "        data = await f.read()\n"
        "        return data\n"
        "    contents = await _read_capped(file)\n"
        "    if len(contents) > MAX_FILE_SIZE:\n"
        "        raise HTTPException(413)\n",
        encoding="utf-8",
    )
    assert UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_upload_no_size_limit_lru_cached_helper_does_not_fire_when_route_caps(tmp_path: Path) -> None:
    # Regression (#452 re-review round 2, HIGH): the fix above kept ANY decorated nested def, and
    # a decorator on a private helper is not a route. `@functools.lru_cache` on the helper
    # resurrected the exact false positive the previous test locks — a correctly-capped route
    # reported as unguarded, on its own private closure.
    (tmp_path / "upload.py").write_text(
        "import functools\n"
        "from fastapi import FastAPI, HTTPException, UploadFile\n\n"
        "app = FastAPI()\n\n"
        "@app.post('/upload')\n"
        "async def upload_endpoint(file: UploadFile):\n"
        "    MAX_FILE_SIZE = 1_000_000\n"
        "    @functools.lru_cache\n"
        "    def _peek(f: UploadFile) -> int:\n"
        "        return 0\n"
        "    contents = await file.read()\n"
        "    if len(contents) > MAX_FILE_SIZE:\n"
        "        raise HTTPException(413)\n",
        encoding="utf-8",
    )
    assert UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_upload_no_size_limit_multi_line_signature_on_unparsable_file(tmp_path: Path) -> None:
    # Regression (#452 re-review round 2, HIGH): a file that does not parse falls back to
    # `_iter_functions_lines`, whose signature-consuming walk clobbered the outer bracket-depth
    # state. A multi-line signature closing at the `def`'s own indent then popped the def's scope
    # before its body, so the private `_read` closure was treated as top-level and reported —
    # a correctly-capped route flagged as unguarded, on any file agentsec can't parse.
    (tmp_path / "upload.py").write_text(
        "from fastapi import FastAPI, HTTPException, UploadFile\n\n"
        "app = FastAPI()\n\n"
        "<<< this line is not python at all >>>\n\n"
        "@app.post('/upload')\n"
        "async def upload_endpoint(\n"
        "    file: UploadFile,\n"
        "    tag: str = 'x',\n"
        ") -> dict:\n"
        "    MAX_FILE_SIZE = 1_000_000\n"
        "    async def _read(f: UploadFile) -> bytes:\n"
        "        return await f.read()\n"
        "    contents = await _read(file)\n"
        "    if len(contents) > MAX_FILE_SIZE:\n"
        "        raise HTTPException(413)\n"
        "    return {}\n",
        encoding="utf-8",
    )
    assert UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_upload_no_size_limit_nested_decorated_route_still_fires(tmp_path: Path) -> None:
    # BLAST-RADIUS LOCK, not a new true positive. An unguarded upload route registered inside a
    # factory, hidden behind an unrelated `max_size` name (a thumbnail-grid dimension) elsewhere
    # in that factory. This already fired on `origin/main` — its per-line `_FUNC_DEF` matched the
    # nested def too — so the test does NOT discriminate, and an earlier version of this comment
    # claiming it as "the true positive #452 legitimately added" was wrong (#452 re-review,
    # Medium 5; measured main -> 1 at :7, branch -> 1 at :7). What it locks is that neither the
    # `iter_functions` migration nor `include_closures=False` may take this finding away.
    (tmp_path / "upload.py").write_text(
        "from fastapi import APIRouter, UploadFile\n\n"
        "def make_router(max_size_of_thumbnail_grid):\n"
        "    router = APIRouter()\n\n"
        "    @router.post('/avatar')\n"
        "    async def upload_avatar(file: UploadFile):\n"
        "        data = await file.read()\n"
        "        return {'n': len(data)}\n\n"
        "    return router\n",
        encoding="utf-8",
    )
    findings = UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith(":7")     # the nested @router.post route, not the factory


def test_upload_aliased_route_decorator_is_its_own_block(tmp_path: Path) -> None:
    # The #452 gate's CRITICAL, measured 1 -> 0 against the INTERMEDIATE commit that introduced
    # the regression, not against `origin/main` (main fires here too). `post = router.post`
    # then `@post(...)` is an
    # ordinary factory idiom. Narrowing `_is_registration` to route/tool decorators (the right fix
    # for the @lru_cache false positive) stopped recognising the alias, so the unguarded route was
    # absorbed into the factory's block — where the SIBLING route's MAX_FILE_SIZE suppressed it.
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter, UploadFile\n"
        "router = APIRouter()\n\n"
        "def register(router):\n"
        "    post = router.post\n\n"
        "    @router.post('/safe')\n"
        "    async def safe(f: UploadFile):\n"
        "        MAX_FILE_SIZE = 10_000_000\n"
        "        if f.size > MAX_FILE_SIZE:\n"
        "            raise ValueError\n"
        "        return {}\n\n"
        "    @post('/unsafe')\n"
        "    async def unsafe(f: UploadFile):\n"
        "        return {}\n",
        encoding="utf-8",
    )
    findings = UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert len(findings) == 1, [f.location for f in findings]


def test_upload_alias_binding_with_a_trailing_comment_is_still_an_alias(tmp_path: Path) -> None:
    # The SAME CRITICAL class as the test above, and it stayed open: `_ROUTE_ALIAS_BINDING`
    # anchored `[ \t]*$` straight after the verb, so the fix's own fixture differed from a live
    # false negative by two spaces and a `#`. Measured 0 (unguarded route silently absorbed into
    # its factory, suppressed by the SIBLING route's cap) -> 1 (#452 gate, finding 3).
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter, UploadFile\n"
        "router = APIRouter()\n\n"
        "def register(router):\n"
        "    post = router.post  # shorthand\n\n"
        "    @router.post('/safe')\n"
        "    async def safe(f: UploadFile):\n"
        "        MAX_FILE_SIZE = 10_000_000\n"
        "        if f.size > MAX_FILE_SIZE:\n"
        "            raise ValueError\n"
        "        return {}\n\n"
        "    @post('/unsafe')\n"
        "    async def unsafe(f: UploadFile):\n"
        "        return {}\n",
        encoding="utf-8",
    )
    findings = UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert len(findings) == 1, [f.location for f in findings]


def test_upload_inner_helper_is_still_a_closure(tmp_path: Path) -> None:
    # The baseline FP-bait for `include_closures=False`: an inner helper that merely RECEIVES the
    # route's UploadFile must stay inside the capped route's block. NOTE this fixture contains no
    # alias binding, so it does NOT exercise the alias rule — the three tests below are the ones
    # that defend the direction the alias widening trades against (#452 gate, finding 4).
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter, UploadFile\n"
        "router = APIRouter()\n\n"
        "@router.post('/safe')\n"
        "async def safe(f: UploadFile):\n"
        "    MAX_FILE_SIZE = 10_000_000\n"
        "    if f.size > MAX_FILE_SIZE:\n"
        "        raise ValueError\n\n"
        "    def inner(g: UploadFile):\n"
        "        return g.filename\n"
        "    return inner(f)\n",
        encoding="utf-8",
    )
    assert UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []


_CAPPED_ROUTE = (
    "from fastapi import APIRouter, UploadFile\n"
    "router = APIRouter()\n\n"
    "@router.post('/upload')\n"
    "async def upload(f: UploadFile):\n"
    "    MAX_FILE_SIZE = 10_000_000\n"
    "    if f.size > MAX_FILE_SIZE:\n"
    "        raise ValueError\n\n"
)
_INNER_HELPER = (
    "    def inner(g: UploadFile):\n"
    "        return g.filename\n"
    "    return inner(f)\n"
)


@pytest.mark.parametrize(
    ("label", "source"),
    [
        # THE TRADED-AGAINST DIRECTION #1 — a binding QUOTED in a docstring is prose, not code.
        # `iter_functions`' ast path read the RAW text, so any module whose docs show the
        # `post = router.post` idiom promoted every bare `@post` inner helper in it to a "route"
        # with no size check. Measured 0 -> 1 on a route that DOES enforce a cap (#452 gate, #1).
        ("module_docstring_binding",
         '"""Module doc.\n\nExample::\n\n    post = router.post\n"""\n'
         + _CAPPED_ROUTE + "    @post\n" + _INNER_HELPER),
        ("function_docstring_binding",
         "from fastapi import APIRouter, UploadFile\n"
         "router = APIRouter()\n\n"
         "@router.post('/upload')\n"
         "async def upload(f: UploadFile):\n"
         '    """Docs.\n\n    post = router.post\n    """\n'
         "    MAX_FILE_SIZE = 10_000_000\n"
         "    if f.size > MAX_FILE_SIZE:\n"
         "        raise ValueError\n\n"
         "    @post\n" + _INNER_HELPER),
        # THE TRADED-AGAINST DIRECTION #2 — the alias door must apply the SAME receiver rule as a
        # direct decorator. `patch = mock.patch` is the ordinary unittest idiom; without the rule
        # it re-admitted the bare `@patch(...)` form that the receiver requirement was added to
        # reject in the first place ("8 hits in the corpus"). Measured 0 -> 1 (#452 gate, #2).
        ("patch_aliased_from_mock",
         "import mock\npatch = mock.patch\n" + _CAPPED_ROUTE
         + "    @patch('svc.store')\n" + _INNER_HELPER),
        ("patch_aliased_from_unittest_mock",
         "import unittest.mock\npatch = unittest.mock.patch\n" + _CAPPED_ROUTE
         + "    @patch('svc.store')\n" + _INNER_HELPER),
        # THE TRADED-AGAINST DIRECTION #3 — a receiver ending in "mock" is a mock patcher, not an
        # HTTP PATCH route. Segment EQUALITY classified all three as routes. Measured 0 -> 1
        # (#452 gate, finding 5).
        ("webmock_patched_helper",
         _CAPPED_ROUTE + "    @webmock.patch('/x')\n" + _INNER_HELPER),
        ("redis_mock_patched_helper",
         _CAPPED_ROUTE + "    @redis_mock.patch('/x')\n" + _INNER_HELPER),
        ("apimock_patched_helper",
         _CAPPED_ROUTE + "    @apimock.patch('/x')\n" + _INNER_HELPER),
        # Controls: neither of these ever bound an alias, and both must stay silent.
        ("no_binding_at_all", _CAPPED_ROUTE + "    @post\n" + _INNER_HELPER),
        ("binding_commented_out",
         "# post = router.post\n" + _CAPPED_ROUTE + "    @post\n" + _INNER_HELPER),
    ],
)
def test_upload_alias_widening_does_not_reopen_the_closure_fp(
    tmp_path: Path, label: str, source: str,
) -> None:
    # The route DOES enforce a cap; only its private inner helper is in question. Anything reported
    # here is a false positive on correct code — the direction `include_closures=False` exists for,
    # re-opened three times inside PR #452 alone.
    (tmp_path / "api.py").write_text(source, encoding="utf-8")
    findings = UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert findings == [], f"{label}: {[f.location for f in findings]}"


def test_upload_no_size_limit_factory_registered_route_reports_once(tmp_path: Path) -> None:
    # Issue #502. The sibling test above (`..._nested_decorated_route_still_fires`) asserts == 1 on
    # this same shape, but only because its factory takes a `max_size_of_thumbnail_grid` parameter,
    # and `max_size` is this guard's own mitigation token — it suppressed the factory's bogus copy.
    # Measured on origin/main: with that name -> 1 finding, renamed to `settings` -> 2 findings, at
    # the factory's `def` and the route's. So this fixture drops the token, which is what makes it
    # discriminate.
    #
    # This guard is not decorator-gated (it gates on the `: UploadFile` PARAMETER), so it reaches
    # the same duplicate by a different door: the factory's block contains the nested route's
    # signature. `include_closures=False` does not help — the factory is top-level, so it is
    # emitted unconditionally.
    (tmp_path / "upload.py").write_text(
        "from fastapi import APIRouter, UploadFile\n\n"
        "def make_router(settings):\n"
        "    router = APIRouter()\n\n"
        "    @router.post('/avatar')\n"
        "    async def upload_avatar(file: UploadFile):\n"
        "        data = await file.read()\n"
        "        return {'n': len(data)}\n\n"
        "    return router\n",
        encoding="utf-8",
    )
    findings = UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith(":7")     # the route, not the factory at :3

def test_upload_no_size_limit_factory_registered_multiline_signature_still_fires(tmp_path: Path) -> None:
    # The shape that decides HOW #502 is fixed. Blanking the nested def out of the factory's block
    # keeps the route's own block whole, so a signature wrapped across lines still shows its
    # `: UploadFile`. Narrowing this guard's gate to a "decorator stack + def line" header slice
    # instead — the fix shape the decorator-gated siblings could have used — would stop at the
    # `async def upload_avatar(` line and lose the annotation, and with it a real finding.
    (tmp_path / "upload.py").write_text(
        "from fastapi import APIRouter, UploadFile\n\n"
        "def make_router(settings):\n"
        "    router = APIRouter()\n\n"
        "    @router.post('/avatar')\n"
        "    async def upload_avatar(\n"
        "        file: UploadFile,\n"
        "    ):\n"
        "        data = await file.read()\n"
        "        return {'n': len(data)}\n\n"
        "    return router\n",
        encoding="utf-8",
    )
    findings = UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith(":7")

def test_upload_no_size_limit_factory_registered_capped_route_silent(tmp_path: Path) -> None:
    # FP-bait: a factory-registered upload route that DOES cap the read stays silent.
    (tmp_path / "upload.py").write_text(
        "from fastapi import APIRouter, HTTPException, UploadFile\n\n"
        "def make_router(settings):\n"
        "    router = APIRouter()\n\n"
        "    @router.post('/avatar')\n"
        "    async def upload_avatar(file: UploadFile):\n"
        "        data = await file.read()\n"
        "        if len(data) > MAX_UPLOAD_SIZE:\n"
        "            raise HTTPException(413)\n"
        "        return {'n': len(data)}\n\n"
        "    return router\n",
        encoding="utf-8",
    )
    assert UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []


def test_upload_no_size_limit_silent_on_nonproduct_path(tmp_path: Path) -> None:
    # Corpus-scan FP: `fastapi/fastapi`'s own `docs_src/` tutorials (already in the
    # shared `is_nonproduct_path` list) over-fired this guard — never called before this fix.
    d = tmp_path / "docs_src"
    d.mkdir()
    (d / "upload.py").write_text(
        "from fastapi import UploadFile\n\nasync def save(file: UploadFile) -> None:\n    data = await file.read()\n",
        encoding="utf-8",
    )
    assert UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []


def test_upload_no_size_limit_still_fires_at_a_normal_path(tmp_path: Path) -> None:
    # Direction traded against (CLAUDE.md rule 1): a sibling non-product directory must not
    # silence the same violation shape at an ordinary path.
    (tmp_path / "docs_src").mkdir()
    (tmp_path / "docs_src" / "upload.py").write_text(
        "from fastapi import UploadFile\n\nasync def save(file: UploadFile) -> None:\n    data = await file.read()\n",
        encoding="utf-8",
    )
    (tmp_path / "upload.py").write_text(
        "from fastapi import UploadFile\n\nasync def save(file: UploadFile) -> None:\n    data = await file.read()\n",
        encoding="utf-8",
    )
    findings = UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert any(f.location.startswith("upload.py") for f in findings)
    assert not any(f.location.startswith("docs_src") for f in findings)


def test_upload_no_size_limit_nested_sibling_route_does_not_cover_the_outer(tmp_path: Path) -> None:
    # Rule 1 lock on the WIDENING #502's fix causes (#605 gate, Medium-1). This guard's mitigation
    # token is a size check rather than auth, but the leak is identical: the inner route's own size
    # guard used to sit inside the outer's scanned block and count as the outer's mitigation, so an
    # unbounded read reported nothing. Measured origin/main -> 0 findings, HEAD -> 1 at the outer.
    (tmp_path / "upload.py").write_text(
        "from fastapi import APIRouter, UploadFile\n\n"
        "@router.post('/upload')\n"
        "async def upload_outer(file: UploadFile):\n"
        "    @router.post('/other')\n"
        "    async def upload_inner(file: UploadFile):\n"
        "        if file.size > max_size:\n"
        "            raise HTTPException(413)\n"
        "        return await file.read()\n"
        "    data = await file.read()\n"
        "    return {'n': len(data)}\n",
        encoding="utf-8",
    )
    findings = UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith(":4")     # the OUTER route


def test_upload_no_size_limit_outer_route_limit_does_not_cover_a_nested_sibling(
    tmp_path: Path,
) -> None:
    # FP-bait mirror: the size check on the outer, the unbounded read on the inner, and the finding
    # lands on the inner. Pins that the blanking did not start moving findings around.
    (tmp_path / "upload.py").write_text(
        "from fastapi import APIRouter, UploadFile\n\n"
        "@router.post('/upload')\n"
        "async def upload_outer(file: UploadFile):\n"
        "    @router.post('/other')\n"
        "    async def upload_inner(file: UploadFile):\n"
        "        return await file.read()\n"
        "    if file.size > max_size:\n"
        "        raise HTTPException(413)\n"
        "    data = await file.read()\n"
        "    return {'n': len(data)}\n",
        encoding="utf-8",
    )
    findings = UploadNoSizeLimitGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith(":6")     # the INNER route


# --- #472 Family B: a size-limiting middleware registered in ANOTHER file -------------------------
# Every case below is multi-file (CLAUDE.md "Adding a check" step 3): the idiomatic app registers
# its middleware once, in `main.py`, and the route under `routes/` carries no trace of it.

_UPLOAD_ROUTE = (
    "from fastapi import APIRouter, UploadFile\n"
    "router = APIRouter()\n"
    "\n"
    "@router.post('/upload')\n"
    "async def ingest(file: UploadFile) -> dict:\n"
    "    data = await file.read()\n"
    "    return {'n': len(data)}\n"
)
_ROUTE_AT = "routes/upload.py:5"
_MAIN_HEAD = (
    "from fastapi import FastAPI\n"
    "from starlette.middleware import Middleware\n"
    "from app_middleware import ContentSizeLimitMiddleware, MaxBytesMiddleware\n"
    "from routes import upload\n"
)
_REGISTER = "app = FastAPI()\napp.add_middleware(ContentSizeLimitMiddleware, max_content_size=10_000_000)\n"


def _tree(root: Path, files: dict[str, str]) -> list[str]:
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    profile = mkprofile(root, features={"python", "fastapi"}, python_dirs=["."])
    return sorted(f.location.replace("\\", "/") for f in UploadNoSizeLimitGuard().run(root, profile))


@pytest.mark.parametrize(
    "main",
    [
        _REGISTER,
        "app = FastAPI(middleware=[Middleware(MaxBytesMiddleware, max_bytes=10_000_000)])\n",
        "import app_middleware as mw\napp = FastAPI()\napp.add_middleware(mw.ContentSizeLimitMiddleware)\n",
        "def create_app() -> FastAPI:\n"
        "    app = FastAPI()\n"
        "    app.add_middleware(ContentSizeLimitMiddleware, max_content_size=10_000_000)\n"
        "    return app\n",
        # #1016 review M1: the keyword spellings of the class argument, and direct ASGI wrapping.
        "app = FastAPI()\napp.add_middleware(middleware_class=ContentSizeLimitMiddleware, max_content_size=1)\n",
        "app = FastAPI(middleware=[Middleware(cls=MaxBytesMiddleware, max_bytes=10_000_000)])\n",
        "app = FastAPI()\napp = ContentSizeLimitMiddleware(app, max_content_size=10_000_000)\n",
    ],
    ids=["add-middleware", "middleware-list", "dotted-reference", "app-factory",
         "keyword-middleware-class", "keyword-cls", "asgi-wrap"],
)
def test_upload_no_size_limit_silent_when_main_py_registers_size_middleware(tmp_path: Path, main: str) -> None:
    # #472 narrowing. Before the fix the route fired, because the guard read only its own file.
    assert _tree(tmp_path, {"main.py": _MAIN_HEAD + main, "routes/upload.py": _UPLOAD_ROUTE}) == []


@pytest.mark.parametrize(
    "main",
    [
        # The control: the imports in `_MAIN_HEAD` alone are a mention, not a registration.
        "app = FastAPI()\n",
        "app = FastAPI()\n# app.add_middleware(ContentSizeLimitMiddleware, max_content_size=10_000_000)\n",
        "app = FastAPI()\nNOTE = 'app.add_middleware(ContentSizeLimitMiddleware)'\n",
        "class ContentSizeLimitMiddleware:\n    pass\n\napp = FastAPI()\n",
        "app = FastAPI()\nif settings.LIMIT_UPLOADS:\n"
        "    app.add_middleware(ContentSizeLimitMiddleware, max_content_size=10_000_000)\n",
        "app = FastAPI()\nif settings.DEBUG:\n    pass\nelse:\n"
        "    app.add_middleware(ContentSizeLimitMiddleware, max_content_size=10_000_000)\n",
        "app = FastAPI()\napp.add_middleware(CORSMiddleware, allow_origins=['https://app.example'])\n",
        # #1016 review L4: the sibling guard's fail-open shape (#1011). A rate limiter, or any other
        # non-size middleware, is no body-size cap, whatever keywords it takes.
        "app = FastAPI()\napp.add_middleware(RateLimitMiddleware, max_content_size=1)\n",
        "app = FastAPI()\napp.add_middleware(TrustedHostMiddleware, allowed_hosts=['app.example'])\n",
        # #1016 review M1, the directions the direct-wrap credit trades against.
        "app = FastAPI()\nif settings.LIMIT_UPLOADS:\n    app = ContentSizeLimitMiddleware(app)\n",
        "app = FastAPI()\nmw = ContentSizeLimitMiddleware()\n",
        "app = FastAPI()\napp = GZipMiddleware(app, minimum_size=500)\n",
        # #1016 round-2 M1: an exception or config class that only contains the name, and a
        # construction around a literal, register nothing.
        "app = FastAPI()\nraise ContentSizeLimitMiddlewareError('too big')\n",
        "app = FastAPI()\ncfg = ContentSizeLimitMiddlewareConfig(1000)\n",
        "app = FastAPI()\nmw = ContentSizeLimitMiddleware(None, max_content_size=None)\n",
    ],
    ids=["import-only", "commented-out", "quoted", "class-definition", "under-if", "under-else",
         "unrelated-middleware", "rate-limit-middleware", "trusted-host-middleware", "asgi-wrap-under-if",
         "constructed-without-app", "other-middleware-wrap", "exception-class", "config-class",
         "literal-argument"],
)
def test_upload_no_size_limit_still_fires_when_main_py_only_mentions_size_middleware(
    tmp_path: Path, main: str
) -> None:
    # Rule 1, the direction traded against: only an unconditional registration is proof.
    assert _tree(tmp_path, {"main.py": _MAIN_HEAD + main, "routes/upload.py": _UPLOAD_ROUTE}) == [_ROUTE_AT]


def test_upload_no_size_limit_registration_covers_its_own_top_level_dir_only(tmp_path: Path) -> None:
    # Monorepo: `svc_a/`'s middleware covers `svc_a/`'s route and not `svc_b/`'s.
    files = {
        "svc_a/main.py": _MAIN_HEAD + _REGISTER,
        "svc_a/routes/upload.py": _UPLOAD_ROUTE,
        "svc_b/main.py": _MAIN_HEAD + "app = FastAPI()\n",
        "svc_b/routes/upload.py": _UPLOAD_ROUTE,
    }
    assert _tree(tmp_path, files) == ["svc_b/routes/upload.py:5"]


def test_upload_no_size_limit_test_only_registration_does_not_cover(tmp_path: Path) -> None:
    # A test app's middleware never runs in front of the product's routes, so `tests/conftest.py`
    # is no coverage source, even under the route's own top-level directory.
    files = {
        "app/main.py": _MAIN_HEAD + "app = FastAPI()\n",
        "app/routes/upload.py": _UPLOAD_ROUTE,
        "app/tests/conftest.py": _MAIN_HEAD + _REGISTER,
    }
    assert _tree(tmp_path, files) == ["app/routes/upload.py:5"]


def test_upload_no_size_limit_pragma_in_main_still_contributes_its_middleware(tmp_path: Path) -> None:
    # CLAUDE.md rule 4: the pragma gates where a finding is anchored, not what pass 1 reads.
    main = "# security: allow-no-upload-size-limit\n" + _MAIN_HEAD + _REGISTER
    assert _tree(tmp_path, {"main.py": main, "routes/upload.py": _UPLOAD_ROUTE}) == []


def test_upload_no_size_limit_unparseable_main_py_gives_no_coverage(tmp_path: Path) -> None:
    # Total: a syntax error in the registering file credits nothing and raises nothing.
    main = _MAIN_HEAD + _REGISTER + "def broken(:\n"
    assert _tree(tmp_path, {"main.py": main, "routes/upload.py": _UPLOAD_ROUTE}) == [_ROUTE_AT]


def test_upload_no_size_limit_skips_pass_1_when_no_route_fires(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # #771 cost class: a repo whose every upload route is capped never pays for the AST pass.
    def boom(*_: object) -> set[str]:
        raise AssertionError("pass 1 ran with no candidate route")

    monkeypatch.setattr("agentsec.guards.upload_no_size_limit.registered_middleware_scopes", boom)
    capped = _UPLOAD_ROUTE.replace("await file.read()", "await file.read(max_size)")
    assert _tree(tmp_path, {"main.py": _MAIN_HEAD + _REGISTER, "routes/upload.py": capped}) == []
