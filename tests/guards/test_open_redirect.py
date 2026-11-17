from __future__ import annotations

from agentsec.guards.open_redirect import OpenRedirectGuard
from tests.guards._common import *  # noqa: F401,F403


def _run(tmp_path: Path):
    return OpenRedirectGuard().run(tmp_path, _pyprof(tmp_path))


# --- true positives: target provably derives from untrusted / request input ---

def test_open_redirect_flags_tainted_request_var(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text(
        "from flask import redirect, request\n"
        "def go():\n    nxt = request.args.get('n')\n    return redirect(nxt)\n",
        encoding="utf-8",
    )
    findings = _run(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule == "open-redirect/user-controlled-target"
    assert findings[0].severity == "medium"


def test_open_redirect_flags_direct_request_arg(tmp_path: Path) -> None:
    # Issue #90 companion FN: a DIRECT `redirect(request.args.get('next'))` used to be MISSED because
    # the arg contains the quoted key `'next'` (the old "no quote => dynamic" heuristic). Must fire now.
    (tmp_path / "v.py").write_text(
        "from flask import redirect, request\n"
        "def go():\n    return redirect(request.args.get('next'))\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 1


def test_open_redirect_flags_request_fstring_and_redirectresponse(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "def go(request):\n    return RedirectResponse(f\"https://{request.query_params['h']}/next\")\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 1


def test_open_redirect_flags_concat_and_chained_taint(tmp_path: Path) -> None:
    (tmp_path / "c.py").write_text(
        "from flask import redirect, request\n"
        "def go():\n"
        "    raw = request.form['u']\n"
        "    dest = raw\n"                       # taint propagates raw -> dest
        "    return redirect('/go?u=' + dest)\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 1


# --- FP-bait: an internal / vetted target must stay silent (issue #90 core) ---

def test_open_redirect_silent_on_internal_bare_var(tmp_path: Path) -> None:
    # The F2/B8 noise the issue is about: a redirect to a plain function param is NOT proven
    # untrusted input and must not fire.
    (tmp_path / "t.py").write_text(
        "from flask import redirect\ndef go(dest):\n    return redirect(dest)\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_silent_on_url_for_derived_var(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "from flask import redirect, url_for\n"
        "def go():\n    target = url_for('dashboard')\n    return redirect(target)\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_silent_on_internal_fstring(tmp_path: Path) -> None:
    # an f-string built from an internal param (not request-derived) is not an open redirect
    (tmp_path / "t.py").write_text(
        "from flask import redirect\ndef go(uid):\n    return redirect(f'/user/{uid}')\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_passes_url_for(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "from flask import redirect, url_for\ndef go():\n    return redirect(url_for('dashboard'))\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_passes_static_literal(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "from flask import redirect\ndef go():\n    return redirect('/home')\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_pragma_opt_out(tmp_path: Path) -> None:
    # a genuinely tainted target (would fire) silenced by the pragma
    (tmp_path / "t.py").write_text(
        "from flask import redirect, request\n"
        "def go():\n    nxt = request.args.get('n')\n"
        "    return redirect(nxt)  # security: allow-open-redirect\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


# --- PR #296 review: taint-precision FP-bait (a tainted name must not collide) ---

def test_open_redirect_silent_on_attribute_name_collision(tmp_path: Path) -> None:
    # FP-1: a tainted var `nxt` must not taint an unrelated attribute `config.nxt`.
    (tmp_path / "t.py").write_text(
        "from flask import redirect, request\n"
        "def h(config):\n    nxt = request.args['n']\n    log(nxt)\n    return redirect(config.nxt)\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_silent_on_kwarg_name_collision(tmp_path: Path) -> None:
    # FP-2: a tainted var `nxt` must not taint a keyword-arg named `nxt=`.
    (tmp_path / "t.py").write_text(
        "from flask import redirect, request\n"
        "def h():\n    nxt = request.args['n']\n    log(nxt)\n    return redirect(url_build(nxt='home'))\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_silent_on_comment_mentioning_request(tmp_path: Path) -> None:
    # FP-3: `request.args` inside a trailing comment must not taint the assignment.
    (tmp_path / "t.py").write_text(
        "from flask import redirect\n"
        "def h():\n    dest = '/home'  # not really from request.args\n    return redirect(dest)\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_silent_on_substring_name(tmp_path: Path) -> None:
    # a tainted `id` must not match inside a longer identifier `user_id`
    (tmp_path / "t.py").write_text(
        "from flask import redirect, request\n"
        "def h(user_id):\n    id = request.args['id']\n    log(id)\n    return redirect(user_id)\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


# --- PR #296 review: taint-propagation FN regressions (each must fire) ---

def test_open_redirect_flags_chained_assignment(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "from flask import redirect, request\n"
        "def h():\n    a = b = request.args['x']\n    return redirect(b)\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 1


def test_open_redirect_flags_tuple_unpack(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "from flask import redirect, request\n"
        "def h():\n    a, b = request.args['x'], 1\n    return redirect(a)\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 1


def test_open_redirect_flags_augmented_assignment(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "from flask import redirect, request\n"
        "def h():\n    p = '/base'\n    p += request.args['s']\n    return redirect(p)\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 1


def test_open_redirect_flags_get_json_and_walrus(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "from flask import redirect, request\n"
        "def h():\n    d = request.get_json()\n    return redirect(d)\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 1
    (tmp_path / "b.py").write_text(
        "from flask import redirect, request\n"
        "def h():\n    if (nxt := request.args.get('n')):\n        pass\n    return redirect(nxt)\n",
        encoding="utf-8",
    )
    # both files now present -> a.py (1) + b.py (1)
    assert len(_run(tmp_path)) == 2


# --- PR #296 round-2: string-literal precision (match code, not string content) ---

def test_open_redirect_silent_on_request_text_in_string(tmp_path: Path) -> None:
    # R2-FP-1: `request.args` as literal text in a string (a URL / message) must not taint.
    (tmp_path / "t.py").write_text(
        "from flask import redirect\n"
        "def h():\n    dest = 'https://site/x/request.args/docs'\n    return redirect(dest)\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_silent_on_tainted_name_as_string_key(tmp_path: Path) -> None:
    # R2-FP-2: a tainted var name reused as a string dict-key elsewhere must not collide.
    (tmp_path / "t.py").write_text(
        "from flask import redirect, request\n"
        "def h(headers):\n    nxt = request.args['n']\n    log(nxt)\n    return redirect(headers['nxt'])\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_silent_on_static_string_literal_target(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "from flask import redirect\ndef h():\n    return redirect('http://x/request.args')\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_flags_walrus_with_nested_call(tmp_path: Path) -> None:
    # R2 minor FN: a nested call before the untrusted ref in a walrus value must not truncate taint.
    (tmp_path / "t.py").write_text(
        "from flask import redirect, request\n"
        "def h():\n    if (y := prefix(safe()) + request.args['a']):\n        pass\n    return redirect(y)\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 1


def test_open_redirect_fstring_interpolation_still_fires(tmp_path: Path) -> None:
    # the string-strip fix must NOT blank an f-string's `{...}` interpolation (real code)
    (tmp_path / "t.py").write_text(
        "from flask import redirect, request\n"
        "def h():\n    return redirect(f\"{request.args['n']}\")\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 1


# --- PR #296 round-3 (tokenize rewrite): lexical-boundary FP-bait + one FN ---

def test_open_redirect_silent_on_sink_text_inside_a_string(tmp_path: Path) -> None:
    # R3 regression: `redirect(request.args...)` as TEXT inside a string (a log/doc/warning)
    # must not be read as a call. The sink is now searched on tokenize-blanked source.
    (tmp_path / "t.py").write_text(
        "from flask import redirect\n"
        "def h():\n"
        "    m = \"avoid: return redirect(request.args.get('next'))\"\n"
        "    log(m)\n"
        "    return redirect('/home')\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_silent_on_keyword_glued_string(tmp_path: Path) -> None:
    # R3: a string glued to a keyword with no space (`else"…"`) is valid Python; its content
    # must be blanked, not leak through.
    (tmp_path / "t.py").write_text(
        "from flask import redirect\n"
        "def h(b):\n    a = '/home'\n    return redirect(a if b else\"http://evil/request.args\")\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_silent_on_multiline_docstring_example(tmp_path: Path) -> None:
    # R3 structural: a redirect code-example INSIDE a multi-line docstring must not fire
    # (the whole triple-quoted span is a string token -> blanked). This is what a line-only
    # model could never close and motivated the tokenize rewrite.
    (tmp_path / "t.py").write_text(
        "from flask import redirect, request\n"
        "def h():\n"
        "    \"\"\"\n"
        "    do not copy this:\n"
        "    nxt = request.args['next']\n"
        "    return redirect(nxt)\n"
        "    \"\"\"\n"
        "    return redirect('/home')\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_flags_fstring_with_format_spec(tmp_path: Path) -> None:
    # R3 FN: an f-string interpolating a request accessor AND carrying a nested format-spec
    # field (`{value:>{width}}`) must still fire — tokenize keeps both interpolation exprs.
    (tmp_path / "t.py").write_text(
        "from flask import redirect, request\n"
        "def h(w):\n    return redirect(f\"{request.args['n']:>{w}}\")\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 1


def test_open_redirect_does_not_crash_on_syntax_error(tmp_path: Path) -> None:
    # tokenize must degrade gracefully (best-effort) on an unparseable file, never raise.
    (tmp_path / "bad.py").write_text("def h(:\n    return redirect(\n", encoding="utf-8")
    OpenRedirectGuard().run(tmp_path, _pyprof(tmp_path))  # no exception


# --- PR #296 re-review: typed FastAPI/Starlette request-data params are untrusted (Marconi) ---
# The taint rewrite recognized only `var = request.X` assignment, so a route's own typed
# `next: str = Query(...)` parameter (the single most common FastAPI redirect-target source)
# went silent though it fires on main. These lock the fix + guard against a #90 FP relapse.

def test_open_redirect_flags_typed_query_param(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "from fastapi import Query\n"
        "from starlette.responses import RedirectResponse\n"
        "@app.get('/go')\n"
        "def go(next: str = Query(...)):\n    return RedirectResponse(next)\n",
        encoding="utf-8",
    )
    findings = _run(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule == "open-redirect/user-controlled-target"


def test_open_redirect_flags_typed_path_and_body_params(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "from fastapi import Path\n"
        "def go(dest: str = Path(...)):\n    return RedirectResponse(dest)\n",
        encoding="utf-8",
    )
    (tmp_path / "b.py").write_text(
        "from fastapi import Body\n"
        "def go(dest: str = Body(...)):\n    return RedirectResponse(dest)\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 2


def test_open_redirect_flags_annotated_query_param(tmp_path: Path) -> None:
    # the modern FastAPI idiom carries the marker in `Annotated[...]` metadata, no default.
    (tmp_path / "t.py").write_text(
        "from typing import Annotated\nfrom fastapi import Query\n"
        "def go(next: Annotated[str, Query()]):\n    return RedirectResponse(next)\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 1


def test_open_redirect_flags_param_taint_transitive_and_multiline(tmp_path: Path) -> None:
    # taint flows from the typed param through an assignment; a multi-line signature works too.
    (tmp_path / "t.py").write_text(
        "from fastapi import Query\n"
        "def go(\n    a: int,\n    nxt: str = Query(...),\n):\n"
        "    dest = nxt\n    return redirect(dest)\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 1


def test_open_redirect_silent_on_untainted_param_beside_marker(tmp_path: Path) -> None:
    # only the marker-bound param is untrusted; redirecting the sibling internal param is silent.
    (tmp_path / "t.py").write_text(
        "from fastapi import Query\n"
        "def go(a: str, next: str = Query(...)):\n    return redirect(a)\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_silent_on_plain_typed_param(tmp_path: Path) -> None:
    # a plain typed param with NO request-data marker stays silent (no #90 FP relapse).
    (tmp_path / "t.py").write_text(
        "from flask import redirect\ndef go(dest: str):\n    return redirect(dest)\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_silent_on_marker_name_collisions(tmp_path: Path) -> None:
    # `Path`/`Query` as ordinary constructors (pathlib, SQLAlchemy) are NOT request bindings:
    # detection is scoped to `def` signatures, so a statement-level assignment must not taint.
    (tmp_path / "a.py").write_text(
        "from pathlib import Path\n"
        "def go(u):\n    p = Path('/tmp')\n    return redirect(p)\n",
        encoding="utf-8",
    )
    (tmp_path / "b.py").write_text(
        "def go():\n    q = Query(User).all()\n    return redirect(q)\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_silent_on_marker_default_without_framework_import(tmp_path: Path) -> None:
    # #296 round-5 review (HIGH): `Path(...)` / `Query(...)` as a PARAMETER DEFAULT in a file that
    # never imports fastapi/starlette is pathlib / SQLAlchemy, NOT a request binding. Marker
    # recognition is gated on the name being imported from the framework, so these stay silent.
    (tmp_path / "a.py").write_text(
        "from pathlib import Path\nfrom flask import redirect\n"
        "def export(out: Path = Path('./reports/x.csv')):\n    dest = out\n    return redirect(dest)\n",
        encoding="utf-8",
    )
    (tmp_path / "b.py").write_text(
        "from sqlalchemy.orm import Query\nfrom flask import redirect\n"
        "def h(q: Query = Query(entities=[])):\n    return redirect(q)\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_silent_on_pathlib_default_even_when_fastapi_imported(tmp_path: Path) -> None:
    # residual-leak guard: the file imports fastapi (for Depends) but `Path` is pathlib — only
    # marker names actually imported from the framework count, so `Path(...)` must not taint.
    (tmp_path / "t.py").write_text(
        "from fastapi import Depends\nfrom pathlib import Path\nfrom flask import redirect\n"
        "def h(out: Path = Path('/x')):\n    return redirect(out)\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_silent_on_lookalike_package_import(tmp_path: Path) -> None:
    # the import gate must match `fastapi`/`fastapi.<sub>` but NOT a lookalike third-party
    # package like `fastapi_utils`, whose `Query` is not the framework's request marker.
    (tmp_path / "t.py").write_text(
        "from fastapi_utils import Query\nfrom flask import redirect\n"
        "def h(q: str = Query(...)):\n    return redirect(q)\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_flags_parenthesized_marker_import(tmp_path: Path) -> None:
    # the marker may arrive via a parenthesized multi-line `from fastapi import (...)` list.
    (tmp_path / "t.py").write_text(
        "from fastapi import (\n    Query,\n    Depends,\n)\n"
        "def go(next: str = Query(...)):\n    return RedirectResponse(next)\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 1


def test_open_redirect_silent_on_shadowed_marker_name(tmp_path: Path) -> None:
    # #296 round-5/6 re-review: imports are resolved with real semantics (AST). When `Query` is
    # imported from fastapi and THEN re-imported from sqlalchemy, the later import wins at runtime,
    # so the name is NOT a framework marker -> silent.
    (tmp_path / "t.py").write_text(
        "from fastapi import FastAPI, Query\n"
        "from sqlalchemy.orm import Query\n"
        "from flask import redirect\n"
        "def report_builder(q: str = Query(entities=[])):\n    return redirect(q)\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_flags_marker_when_framework_import_wins_by_order(tmp_path: Path) -> None:
    # #296 round-6 (Medium): last-binding-wins — a fastapi import AFTER a same-named non-framework
    # one rebinds the name to the framework marker, so it MUST fire.
    (tmp_path / "t.py").write_text(
        "from sqlalchemy.orm import Query\n"
        "from fastapi import Query\n"
        "from flask import redirect\n"
        "def go(n: str = Query(...)):\n    return redirect(n)\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 1


def test_open_redirect_flags_semicolon_chained_and_backslash_marker_imports(tmp_path: Path) -> None:
    # #296 round-5/6 (Low/High FNs): a `;`-chained second import, a trailing `;` statement, and a
    # `\`-continued list must not hide a genuine framework marker import.
    (tmp_path / "a.py").write_text(
        "from sqlalchemy.orm import Query; from fastapi import Path\n"
        "from flask import redirect\n"
        "def go(next: str = Path(...)):\n    return redirect(next)\n",
        encoding="utf-8",
    )
    (tmp_path / "b.py").write_text(
        "from fastapi import Query, \\\n    Path\n"
        "def go(next: str = Path(...)):\n    return redirect(next)\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 2


def test_open_redirect_flags_aliased_framework_marker(tmp_path: Path) -> None:
    # #296 round-6: AST resolves aliases, so `from fastapi import Query as Q` makes `Q` a marker.
    (tmp_path / "t.py").write_text(
        "from fastapi import Query as Q\n"
        "from flask import redirect\n"
        "def go(n: str = Q(...)):\n    return redirect(n)\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 1


def test_open_redirect_flags_marker_despite_aliased_nonframework_lookalike(tmp_path: Path) -> None:
    # #296 round-6 (Medium-High): an aliased non-framework import (`Query as SAQuery`) binds a
    # DIFFERENT name, so it must not falsely shadow a genuine `from fastapi import Query`.
    (tmp_path / "t.py").write_text(
        "from sqlalchemy.orm import Query as SAQuery\n"
        "from fastapi import Query\n"
        "from flask import redirect\n"
        "def go(n: str = Query(...)):\n    return redirect(n)\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 1


def test_open_redirect_silent_on_relative_import_marker(tmp_path: Path) -> None:
    # a relative import (`from . import Query`) is never the framework marker.
    (tmp_path / "t.py").write_text(
        "from . import Query\nfrom flask import redirect\n"
        "def go(q: str = Query(...)):\n    return redirect(q)\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


# --- PR #296 whole-PR final review: taint-model correctness ---

def test_open_redirect_flags_url_for_concatenated_with_untrusted(tmp_path: Path) -> None:
    # #296 final (High): a `url_for(...)` that is only a SUBSTRING of the target (concatenated
    # with untrusted input) must not suppress the check — only a SOLE url_for target is safe.
    (tmp_path / "t.py").write_text(
        "from flask import redirect, url_for, request\n"
        "def go():\n    return redirect(url_for('x') + request.args['n'])\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 1


def test_open_redirect_silent_on_untrusted_inside_url_for(tmp_path: Path) -> None:
    # the whole target is a url_for(...) call — untrusted lives only inside its args (a vetted
    # internal path), so it stays silent. (Guards the bracket-aware arg extraction.)
    (tmp_path / "t.py").write_text(
        "from flask import redirect, url_for, request\n"
        "def go():\n    return redirect(url_for('p', n=request.args['n']))\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_flags_annotated_with_nested_generic(tmp_path: Path) -> None:
    # #296 final (High): `Annotated[Optional[str], Query()]` — a nested generic — must still be
    # recognized as a typed request param (the old bracket-bounded regex could not cross `]`).
    (tmp_path / "t.py").write_text(
        "from typing import Annotated, Optional\nfrom fastapi import Query\n"
        "def go(n: Annotated[Optional[str], Query()]):\n    return RedirectResponse(n)\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 1


def test_open_redirect_flags_untrusted_keyword_url_arg(tmp_path: Path) -> None:
    # #296 final (Medium): the redirect target in a later / keyword argument (`url=...`) must be
    # inspected, not just the first positional argument.
    (tmp_path / "t.py").write_text(
        "def go(request):\n"
        "    return RedirectResponse(status_code=302, url=request.query_params['n'])\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 1


def test_open_redirect_silent_on_untrusted_in_non_target_kwarg(tmp_path: Path) -> None:
    # untrusted input in a NON-target keyword arg (`headers=`) is not an open redirect -> silent.
    (tmp_path / "t.py").write_text(
        "def go(request):\n"
        "    return RedirectResponse(url='/home', headers={'X': request.args['h']})\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_flags_untrusted_in_nested_call(tmp_path: Path) -> None:
    # bracket-aware arg extraction: `redirect(build(request.args['n']))` is a tainted target.
    (tmp_path / "t.py").write_text(
        "from flask import redirect, request\n"
        "def go():\n    return redirect(build(request.args['n']))\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 1


def test_open_redirect_silent_on_url_for_result_transform(tmp_path: Path) -> None:
    # #296 re-review (Medium): a transform on a url_for result (`url_for(...).lower()`) is still a
    # vetted internal path — the untrusted lives only inside url_for's args, so it stays silent.
    (tmp_path / "t.py").write_text(
        "from flask import redirect, url_for, request\n"
        "def go():\n    return redirect(url_for('p', n=request.args['n']).lower())\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_silent_on_parenthesized_url_for(tmp_path: Path) -> None:
    # #296 re-review (Low): redundant parens around a url_for(...) with untrusted only inside must
    # not defeat the vetted-path recognition.
    (tmp_path / "t.py").write_text(
        "from flask import redirect, url_for, request\n"
        "def go():\n    return redirect((url_for('p', n=request.args['n'])))\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_silent_on_marker_call_outside_annotated(tmp_path: Path) -> None:
    # #296 re-review (Low): a marker-named CALL in a non-`Annotated` annotation (`Dict[str, Query()]`)
    # is not a request binding — the marker-call check is scoped to `Annotated[...]`.
    (tmp_path / "t.py").write_text(
        "from fastapi import Query\n"
        "def go(n: Dict[str, Query()] = None):\n    return RedirectResponse(n)\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_taint_fixpoint_is_not_superlinear(tmp_path: Path) -> None:
    # #296 final + re-review (High/Medium): a long dependent-assignment chain must not blow up
    # (was O(n^3): ~9s at 1500; a plain in-place sweep was still O(n^2) on a REVERSE-order chain).
    # The worklist fixpoint is O(V+E) and order-independent — both orders run well under a second;
    # a generous bound catches a regression to a super-linear form without being flaky.
    import time

    n = 4000
    forward = ["from flask import redirect, request", "def go():", "    v0 = request.args['n']"]
    forward += [f"    v{i} = v{i - 1}" for i in range(1, n)]
    forward.append(f"    return redirect(v{n - 1})")
    reverse = ["from flask import redirect, request", "def go():"]
    reverse += [f"    v{i} = v{i + 1}" for i in range(n - 1)]  # dependents BEFORE their source
    reverse += [f"    v{n - 1} = request.args['n']", "    return redirect(v0)"]
    for name, body in (("fwd.py", forward), ("rev.py", reverse)):
        (tmp_path / name).write_text("\n".join(body) + "\n", encoding="utf-8")
        start = time.monotonic()
        _run(tmp_path)
        # actual <0.3s serial; 15.0s leaves headroom for -n auto/CI contention while
        # still well under what a cubic/quadratic regression would take at n=4000 (~60-170s+)
        assert time.monotonic() - start < 15.0
    assert len(_run(tmp_path)) == 2  # both files fire


def test_open_redirect_silent_on_multiple_url_for_concat(tmp_path: Path) -> None:
    # #296 round-8: every url_for(...) span is blanked, so a concat of two vetted url_for calls
    # (no untrusted outside them) stays silent.
    (tmp_path / "t.py").write_text(
        "from flask import redirect, url_for\n"
        "def go():\n    return redirect(url_for('a') + url_for('b'))\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_open_redirect_flags_multiple_url_for_plus_untrusted(tmp_path: Path) -> None:
    # untrusted surviving OUTSIDE the url_for spans still fires.
    (tmp_path / "t.py").write_text(
        "from flask import redirect, url_for, request\n"
        "def go():\n    return redirect(url_for('a') + url_for('b') + request.args['n'])\n",
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 1


def test_open_redirect_blank_url_for_calls_is_linear(tmp_path: Path) -> None:
    # #296 round-8 (Medium): the `_blank_url_for_calls` HELPER must be a single O(n) pass, not a
    # repeated search-from-start (was O(n^2): ~8s at 8000 calls). Tests the helper in isolation.
    import time

    from agentsec.guards.open_redirect import _blank_url_for_calls

    expr = " + ".join("url_for('x')" for _ in range(20000))
    start = time.monotonic()
    _blank_url_for_calls(expr)
    assert time.monotonic() - start < 3.0  # actual ~0.01s; an O(n^2) form would exceed this


def test_open_redirect_scan_is_linear_on_realistic_multiline(tmp_path: Path) -> None:
    # #296 round-8 re-review (Medium): end-to-end, the guard is linear on realistic code (many
    # redirect statements across separate lines). The residual per-line `tokenize` cost only bites
    # a single pathologically-long line (documented in the design doc), which real code never has.
    import time

    n = 4000
    lines = ["from flask import redirect, url_for", "def go():"]
    lines += [f"    a{i} = redirect(url_for('x'))" for i in range(n)]
    (tmp_path / "t.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
    start = time.monotonic()
    _run(tmp_path)
    assert time.monotonic() - start < 5.0  # actual ~0.15s at 4000 statements


def test_open_redirect_na_without_python() -> None:
    assert OpenRedirectGuard().applies(mkprofile(Path("/tmp"), features={"frontend"})) is False


def test_open_redirect_survives_deeply_nested_file(tmp_path: Path) -> None:
    # #370: `_imported_markers` (and the guard) must stay total on a deeply nested file whose
    # ast.parse raises MemoryError ("Parser stack overflowed"). Degrades to no markers / no crash.
    from agentsec.guards.open_redirect import _imported_markers

    deep = "x = " + "-" * 7000 + "1\n"
    assert _imported_markers(deep) == set()
    (tmp_path / "app.py").write_text(deep, encoding="utf-8")
    _run(tmp_path)  # the guard must not raise


def test_open_redirect_self_attr_assignment_does_not_taint_self(tmp_path: Path) -> None:
    # #423 FP-bait: `self.q = request.args.get("q")` used to taint `self`, so EVERY
    # `redirect(self.anything)` in the file fired. Dropping self/cls from targets fixes it.
    (tmp_path / "v.py").write_text(
        "from flask import redirect, request\n"
        "class View:\n"
        "    def load(self):\n"
        '        self.q = request.args.get("q")\n'
        "    def go(self):\n"
        "        return redirect(self.base_url)\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def _tainted_redirect(tail: str, before: str = "") -> str:
    return (
        "from flask import redirect, request\n"
        f"{before}"
        "def go():\n    nxt = request.args.get('n')\n"
        f"    return redirect(nxt){tail}\n"
    )


def test_open_redirect_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string on the sink line is not a comment; neutral run = control.
    # It used to be matched on the raw line on every path, not only the tokenize fallback.
    for note in ("# reviewed", "# security: allow-open-redirect"):
        (tmp_path / "t.py").write_text(_tainted_redirect(f'; _note = "{note}"'), encoding="utf-8")
        assert len(_run(tmp_path)) == 1, note


def test_open_redirect_pragma_comment_still_suppresses_after_a_form_feed(tmp_path: Path) -> None:
    # #1040: the pragma lines are numbered as the lexer splits the file (on "\n" only). A form feed
    # is a line break to `str.splitlines`, so numbering the view that way would shift every pragma
    # below it onto the wrong line and void the opt-out (rule 4).
    for tail, n in (("", 1), ("  # security: allow-open-redirect", 0)):
        (tmp_path / "t.py").write_text(_tainted_redirect(tail, before="\x0c\n"), encoding="utf-8")
        assert len(_run(tmp_path)) == n, tail


def test_open_redirect_pragma_comment_still_suppresses_in_an_untokenizable_file(tmp_path: Path) -> None:
    # #1040: on a tokenize error the lexer falls back to raw lines, and the comment view keeps the
    # tail raw: a real comment there still suppresses, as the old raw-line fallback did.
    broken = "x = '''unterminated\n"
    for tail, n in (("", 1), ("  # security: allow-open-redirect", 0)):
        (tmp_path / "t.py").write_text(_tainted_redirect(tail) + broken, encoding="utf-8")
        assert len(_run(tmp_path)) == n, tail
