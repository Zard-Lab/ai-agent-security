from __future__ import annotations

import time

import pytest

from agentsec.guards.path_traversal import PathTraversalGuard
from tests._timing import TimingBudget, assert_within, register
from tests.guards._common import *  # noqa: F401,F403


def test_path_traversal_flags_send_file_concat(tmp_path: Path) -> None:
    (tmp_path / "s.py").write_text(
        "from flask import send_file\ndef d(name):\n    return send_file('/data/' + name)\n", encoding="utf-8"
    )
    findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "path-traversal/unsanitized-path"
    assert findings[0].severity == "high"

def test_path_traversal_flags_open_join_var(tmp_path: Path) -> None:
    (tmp_path / "o.py").write_text(
        "import os\ndef r(name):\n    return open(os.path.join('/data', name)).read()\n", encoding="utf-8"
    )
    assert len(PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))) == 1

def test_path_traversal_passes_resolved(tmp_path: Path) -> None:
    # the safety marker (.resolve()/is_relative_to) on the line suppresses the finding
    (tmp_path / "s.py").write_text(
        "from flask import send_file\ndef d(name):\n"
        "    return send_file('/data/' + name)  # checked with .resolve() + is_relative_to\n", encoding="utf-8"
    )
    assert PathTraversalGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_path_traversal_passes_static_and_bare_open(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("def r():\n    return open('config.toml').read()\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("def r(fh):\n    return open(fh).read()\n", encoding="utf-8")
    assert PathTraversalGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_path_traversal_passes_all_literal_join(tmp_path: Path) -> None:
    # #423 FP-bait: a fully STATIC os.path.join — its literals merely contain identifier
    # chars (`x`, `txt`), which must not be read as a bare-variable path component.
    (tmp_path / "a.py").write_text("import os\ndef r():\n    return open(os.path.join('data', 'x.txt')).read()\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("import os\ndef r():\n    return open(os.path.join('data', r'sub.txt')).read()\n", encoding="utf-8")
    assert PathTraversalGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_path_traversal_passes_app_internal_join_roots(tmp_path: Path) -> None:
    # PR #444 re-review: a join rooted at an app-internal path (an ALL-CAPS constant, a
    # settings./config. attr, self./app. attr) is not user-controllable — must NOT fire.
    (tmp_path / "a.py").write_text("import os\ndef r():\n    return open(os.path.join(BASE_DIR, 'config.json')).read()\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("import os\ndef r():\n    return open(os.path.join(settings.DATA_DIR, 'x.txt')).read()\n", encoding="utf-8")
    (tmp_path / "c.py").write_text("import os\ndef r(self):\n    return open(os.path.join(self.root, 'index.html')).read()\n", encoding="utf-8")
    assert PathTraversalGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_path_traversal_flags_variable_dir_with_static_filename(tmp_path: Path) -> None:
    # PR #444 review (Critical): a VARIABLE directory with a static filename is still
    # traversal-prone (`var` may be user-controlled) — the string-blanking fix must not
    # suppress it. os.path.join(var, 'static.txt') must fire.
    (tmp_path / "c.py").write_text(
        "import os\ndef r(var):\n    return open(os.path.join(var, 'static.txt')).read()\n", encoding="utf-8"
    )
    findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "path-traversal/unsanitized-path"

def test_path_traversal_pragma(tmp_path: Path) -> None:
    (tmp_path / "s.py").write_text(
        "from flask import send_file\ndef d(name):\n"
        "    return send_file('/data/' + name)  # security: allow-path-traversal\n", encoding="utf-8"
    )
    assert PathTraversalGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_path_traversal_na_without_python() -> None:
    assert PathTraversalGuard().applies(mkprofile(Path("/tmp"), features={"frontend"})) is False


# Rule B: load_prompt / load_prompt_from_config with dynamic arg

def test_path_traversal_load_prompt_owned_by_dedicated_guard(tmp_path: Path) -> None:
    """load_prompt traversal is owned by `langchain-load-prompt-traversal`, NOT this guard
    (the duplicate path-traversal/langchain-load-prompt rule was dropped to avoid double-fire)."""
    (tmp_path / "lp.py").write_text(
        "from langchain.prompts import load_prompt\n"
        "def get(name):\n"
        "    return load_prompt(name)\n",
        encoding="utf-8",
    )
    findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
    assert not any(f.rule == "path-traversal/langchain-load-prompt" for f in findings)


# Rule C: Path() constructor with dynamic arg

def test_path_traversal_path_ctor_dynamic_fires(tmp_path: Path) -> None:
    # Rule C fires on f-string / concat assembled args (not bare variables)
    (tmp_path / "pc.py").write_text(
        "from pathlib import Path\n"
        "def open_file(base, name):\n"
        '    return Path(f"{base}/{name}").read_text()\n',
        encoding="utf-8",
    )
    findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
    rules = {f.rule for f in findings}
    assert "path-traversal/path-constructor" in rules


def test_path_traversal_path_ctor_fstring_fires(tmp_path: Path) -> None:
    (tmp_path / "pc.py").write_text(
        "from pathlib import Path\n"
        "def open_file(base, name):\n"
        '    return Path(f"{base}/{name}").read_text()\n',
        encoding="utf-8",
    )
    findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
    rules = {f.rule for f in findings}
    assert "path-traversal/path-constructor" in rules


def test_path_traversal_path_ctor_hardcoded_safe(tmp_path: Path) -> None:
    (tmp_path / "pc.py").write_text(
        "from pathlib import Path\n"
        'BASE = Path("/hardcoded/data")\n',
        encoding="utf-8",
    )
    findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
    rules = {f.rule for f in findings}
    assert "path-traversal/path-constructor" not in rules


def test_path_traversal_path_ctor_dunder_file_safe(tmp_path: Path) -> None:
    (tmp_path / "pc.py").write_text(
        "from pathlib import Path\n"
        "HERE = Path(__file__).parent\n",
        encoding="utf-8",
    )
    findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
    rules = {f.rule for f in findings}
    assert "path-traversal/path-constructor" not in rules


# Rule A: LLM output used as file path (MEDUSA-OUTPUT-PATH-001)

def test_path_traversal_llm_output_as_path_fires(tmp_path: Path) -> None:
    (tmp_path / "llmpath.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "llm = ChatOpenAI()\n"
        "def handle(q):\n"
        "    response = llm.invoke(q)\n"
        '    return open(response, "r").read()\n',
        encoding="utf-8",
    )
    findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
    rules = {f.rule for f in findings}
    assert "path-traversal/llm-output-as-path" in rules
    crits = [f for f in findings if f.rule == "path-traversal/llm-output-as-path"]
    assert crits[0].severity == "critical"


def test_path_traversal_llm_output_to_shutil_rmtree_fires(tmp_path: Path) -> None:
    # (llm-seclint's LlmPathTraversalRule): widened sink list — a destructive
    # file-mutation sink is the same traversal risk one step further (delete, not just read).
    (tmp_path / "llmpath.py").write_text(
        "import shutil\n"
        "from langchain_openai import ChatOpenAI\n"
        "llm = ChatOpenAI()\n"
        "def cleanup(q):\n"
        "    response = llm.invoke(q)\n"
        "    shutil.rmtree(response)\n",
        encoding="utf-8",
    )
    findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
    rules = {f.rule for f in findings}
    assert "path-traversal/llm-output-as-path" in rules


def test_path_traversal_llm_output_to_os_remove_fires(tmp_path: Path) -> None:
    (tmp_path / "llmpath.py").write_text(
        "import os\n"
        "from langchain_openai import ChatOpenAI\n"
        "llm = ChatOpenAI()\n"
        "def delete_file(q):\n"
        "    response = llm.invoke(q)\n"
        "    os.remove(response)\n",
        encoding="utf-8",
    )
    findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
    rules = {f.rule for f in findings}
    assert "path-traversal/llm-output-as-path" in rules


def test_path_traversal_shutil_copy_static_paths_silent(tmp_path: Path) -> None:
    # FP-bait: shutil.copy between two hardcoded, non-LLM paths must not fire on the widened
    # sink list — nothing here is model output.
    (tmp_path / "backup.py").write_text(
        "import shutil\n"
        "def backup():\n"
        '    shutil.copy2("/data/app.db", "/backup/app.db.bak")\n',
        encoding="utf-8",
    )
    findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
    assert not any(f.rule == "path-traversal/llm-output-as-path" for f in findings)


def test_path_traversal_llm_output_via_content_proxy_fires(tmp_path: Path) -> None:
    (tmp_path / "llmpath.py").write_text(
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "def handle(q):\n"
        "    resp = client.chat.completions.create(model='gpt-4o', messages=[])\n"
        "    return open(resp.content, 'r').read()\n",
        encoding="utf-8",
    )
    findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
    rules = {f.rule for f in findings}
    assert "path-traversal/llm-output-as-path" in rules


def test_path_traversal_open_user_input_not_llm_output_path(tmp_path: Path) -> None:
    # plain user_input open is caught as HIGH unsanitized-path, NOT as llm-output-as-path
    (tmp_path / "s.py").write_text(
        'def d(name):\n    return open("/data/" + name)\n',
        encoding="utf-8",
    )
    findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
    rules = {f.rule for f in findings}
    assert "path-traversal/llm-output-as-path" not in rules
    assert "path-traversal/unsanitized-path" in rules



# ── FP-bait regressions (review fixes) ───────────────────────────────────────

def test_path_ctor_config_attr_exempt(tmp_path: Path) -> None:
    """`Path(f"{settings.DATA_DIR}/{x}")` is app-internal config assembly — must NOT fire."""
    (tmp_path / "p.py").write_text(
        "from pathlib import Path\n"
        "def f(x):\n"
        '    return Path(f"{settings.DATA_DIR}/{x}")\n',
        encoding="utf-8",
    )
    findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
    assert not any(f.rule == "path-traversal/path-constructor" for f in findings)


def test_path_ctor_dynamic_is_medium(tmp_path: Path) -> None:
    """Rule C is MEDIUM (construction is one step removed from a file operation)."""
    (tmp_path / "p.py").write_text(
        "from pathlib import Path\n"
        "def f(base, name):\n"
        '    return Path(f"{base}/{name}")\n',
        encoding="utf-8",
    )
    findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
    hit = next(f for f in findings if f.rule == "path-traversal/path-constructor")
    assert hit.severity == "medium"


def test_llm_output_path_not_orm_create(tmp_path: Path) -> None:
    """`obj = User.objects.create(...)` is ORM, not an LLM call — open(obj) must NOT fire Rule A."""
    (tmp_path / "a.py").write_text(
        "def f():\n"
        "    obj = User.objects.create(name='x')\n"
        "    return open(obj.path)\n",
        encoding="utf-8",
    )
    findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
    assert not any(f.rule == "path-traversal/llm-output-as-path" for f in findings)


def test_llm_output_path_not_cross_function(tmp_path: Path) -> None:
    """An LLM var in one function and open(var) in another must NOT associate (Rule A scope)."""
    (tmp_path / "a.py").write_text(
        "def a(llm):\n"
        "    response = llm.invoke('q')\n"
        "    return response\n"
        "def b(response):\n"
        "    return open(response)\n",
        encoding="utf-8",
    )
    findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
    assert not any(f.rule == "path-traversal/llm-output-as-path" for f in findings)


def test_path_traversal_trusted_root_exempts_only_the_base_dir(tmp_path: Path) -> None:
    # Regression (#444 review): the trusted-root blanking applied to the WHOLE join argument
    # list, and its vocabulary includes `self.`, `config.`, `app.` and any ALL-CAPS token — so
    # a trusted-looking token in ANY position silenced the call. `self.filename` assigned
    # straight from `request.args.get()` produced no finding from any guard. `self.x` is the
    # absence of information about a value's source, not evidence that it is trusted.
    src = (
        "import os\nfrom flask import request, send_file\n"
        "UPLOAD_DIR = '/srv/uploads'\n"
        "def get():\n"
        "    {assign}\n"
        "    return send_file(os.path.join(UPLOAD_DIR, {arg}))\n"
    )
    for name, assign, arg in (
        ("a.py", "self.filename = request.args.get('f')", "self.filename"),
        ("b.py", "config.name = request.args.get('f')", "config.name"),
        ("c.py", "app.target = request.args.get('f')", "app.target"),
        ("d.py", "USERFILE = request.args.get('f')", "USERFILE"),
    ):
        (tmp_path / name).write_text(src.format(assign=assign, arg=arg), encoding="utf-8")
    assert len(PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))) == 4


def test_path_traversal_trusted_constant_in_middle_position_is_exempt(tmp_path: Path) -> None:
    # FP (#423, PR #444 re-review): restricting the trusted-root exemption to the FIRST join
    # argument false-positived on a legitimate 3+-argument join whose app-internal constant
    # sits in a MIDDLE position. `CONFIG_SUBDIR` is exactly the shape the exemption exists to
    # recognise, it is simply not at index 0. The exemption now covers the whole LEADING RUN
    # of trusted components (constants and string literals), so these must NOT fire.
    for name, src in (
        ("a.py", 'return open(os.path.join(BASE_DIR, CONFIG_SUBDIR, "report.txt"))'),
        ("b.py", 'return open(os.path.join(BASE_DIR, A_DIR, B_DIR, C_DIR, "r.txt"))'),
        ("c.py", 'return open(os.path.join(BASE_DIR, "sub", CONFIG_SUBDIR, "r.txt"))'),
        ("d.py", 'return open(os.path.join(settings.DATA_DIR, CONFIG_SUBDIR, "r.txt"))'),
        ("e.py", 'return send_file(os.path.join(BASE_DIR, CONFIG_SUBDIR, "r.txt"))'),
    ):
        (tmp_path / name).write_text(f"import os\ndef r():\n    {src}\n", encoding="utf-8")
    assert PathTraversalGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_path_traversal_taint_after_a_leading_run_of_trusted_roots_still_fires(tmp_path: Path) -> None:
    # The leading-run exemption is a SUPPRESSION, so it must stop at the first argument that is
    # not recognisably app-internal. Every shape here puts user-controllable data at or after
    # that point and must still fire: an attribute (the absence of information about a source),
    # a lowercase local, a composite expression built from a constant, and an ALL-CAPS name the
    # file assigns from request input (constant-looking, but not a constant).
    src = "import os\nfrom flask import request, send_file\n{body}\n"
    for name, body in (
        ("a.py", 'def r(self):\n    return open(os.path.join(BASE_DIR, SUB, self.filename))'),
        ("b.py", 'def r():\n    return open(os.path.join(BASE_DIR, SUB, config.name))'),
        ("c.py", 'def r(user_dir):\n    return open(os.path.join(BASE_DIR, SUB, user_dir))'),
        ("d.py", 'def r(user_dir):\n    return open(os.path.join(BASE_DIR, user_dir, SUB))'),
        ("e.py", 'def r():\n    return open(os.path.join(BASE_DIR, SUB, request.args["p"]))'),
        ("f.py", 'def r(u):\n    return open(os.path.join(BASE_DIR, SUB + u, "r.txt"))'),
        ("g.py", 'def r(u):\n    return open(os.path.join(BASE_DIR, DIRS[u], "r.txt"))'),
        ("h.py", 'def r(u):\n    return send_file(os.path.join(BASE_DIR, SUB, u))'),
        ("i.py", 'def r():\n    DEST = request.args.get("d")\n'
                 '    return open(os.path.join(BASE_DIR, SUB, DEST))'),
        ("j.py", 'def r():\n    if (DEST := request.args.get("d")):\n'
                 '        return open(os.path.join(BASE_DIR, SUB, DEST))'),
        ("k.py", 'def r():\n    for DEST in request.args.getlist("d"):\n'
                 '        return open(os.path.join(BASE_DIR, SUB, DEST))'),
        ("l.py", 'def r():\n    A, DEST = "x", request.args.get("d")\n'
                 '    return open(os.path.join(BASE_DIR, SUB, DEST))'),
    ):
        (tmp_path / name).write_text(src.format(body=body), encoding="utf-8")
    findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 12, sorted(f.location for f in findings)
    assert {f.rule for f in findings} == {"path-traversal/unsanitized-path"}


def test_path_traversal_trusted_root_in_base_position_still_exempt(tmp_path: Path) -> None:
    # FP-bait, and the case the exemption exists for: an app-internal ROOT joined with a
    # literal is not user-controllable. Only the base-dir position is exempted.
    (tmp_path / "a.py").write_text(
        "import os\ndef r():\n    return open(os.path.join(UPLOAD_DIR, 'static.txt')).read()\n",
        encoding="utf-8",
    )
    (tmp_path / "b.py").write_text(
        "import os\ndef r():\n    return open(os.path.join(settings.DATA_DIR, 'x.txt')).read()\n",
        encoding="utf-8",
    )
    (tmp_path / "c.py").write_text(
        "import os\ndef r(self):\n    return open(os.path.join(self.base_dir, 'i.html')).read()\n",
        encoding="utf-8",
    )
    assert PathTraversalGuard().run(tmp_path, _pyprof(tmp_path)) == []


_TAINT_HEAD = "import os\nfrom flask import request\nBASE_DIR = '/srv/app'\n"
_TAINT_SINK = "open(os.path.join(BASE_DIR, {name})).read()\n"


@pytest.mark.parametrize(
    ("label", "binding", "used"),
    [
        # The three shapes the #444 gate measured going 1 -> 0. Each binds a request-sourced value
        # to an ALL-CAPS name that then reads as a "trusted constant" past the base-dir position.
        ("augmented", "SUB = 'x'\nSUB += request.args.get('d')\n", "SUB"),
        ("chained", "SUB = OTHER = request.args.get('d')\n", "OTHER"),
        ("semicolon-joined", "x = 1; SUB = request.args.get('d')\n", "SUB"),
        # Forms that already worked — pinned so the statement rewrite cannot drop one.
        ("plain", "SUB = request.args.get('d')\n", "SUB"),
        ("annotated", "SUB: str = request.args.get('d')\n", "SUB"),
        ("tuple", "SUB, OTHER = request.args.get('d'), 1\n", "SUB"),
        # Pinned EXPLICITLY, not incidentally: the #444 gate noted the walrus and for-target arms
        # were only covered by another test's fixtures, so the net was a net over the reported
        # instances rather than over the mechanism.
        ("walrus", "if (SUB := request.args.get('d')):\n    pass\n", "SUB"),
        ("for-target", "for SUB in request.args.getlist('d'):\n    pass\n", "SUB"),
        # THE TRADED-AGAINST DIRECTION for the statement rewrite (#444 gate, 2026-08-03). Both
        # partitions the rewrite introduced (source into statements, statement head into
        # targets) were both text splits, and each silently un-tainted a name the previous line-based regex
        # caught. Each case below measured 1 -> 0 at the rewrite.
        #
        # F1: a subscripted annotation carries its own commas. Splitting the target segment on
        # EVERY comma shreds it, and the resulting non-target piece discards the whole chain.
        ("annotated-subscript", "SUB: dict[str, str] = request.args.get('d')\n", "SUB"),
        ("annotated-tuple-type", "SUB: Tuple[str, int] = request.args.get('d')\n", "SUB"),
        # ... and the chain amplification: OTHER is a perfectly well-formed target that the
        # `break` threw away along with the malformed piece.
        ("annotated-subscript-chain",
         "SUB: Dict[str, str] = OTHER = request.args.get('d')\n", "OTHER"),
        ("annotated-nested-subscript",
         "SUB: Dict[str, List[Tuple[int, str]]] = request.args.get('d')\n", "SUB"),
        # F2: `strip_python_strings` blanks TRIPLE-quoted content only, so a `;` inside an
        # ordinary literal survived to the statement split and cut the statement in half.
        # `x.split(';')` is ordinary cookie / header / Content-Type code.
        ("semicolon-in-literal",
         "RAW = 'a;b'\nSUB = RAW.split(';')[0] + request.args.get('d')\n", "SUB"),
        ("semicolon-literal-join", "SUB = ';'.join(request.args.getlist('d'))\n", "SUB"),
        ("semicolon-literal-arg",
         "DEFAULTS = {}\nSUB = DEFAULTS.get('a;b') or request.args.get('d')\n", "SUB"),
        # Both partitions failing at once.
        ("annotated-subscript-and-semicolon",
         "SUB: dict[str, str] = ';'.join(request.args.getlist('d'))\n", "SUB"),
        # The neutralisation has to be NARROW: an f-string body is code, so masking the literal's
        # `;`/`,`/`=` is right but DELETING the literal is not: it takes the interpolated request
        # source with it and re-opens the same class one layer down.
        ("f-string interpolation", "SUB = f\"{request.args.get('d')}\"\n", "SUB"),
        ("f-string with a semicolon", "SUB = f\"a;{request.args['d']}\"\n", "SUB"),
    ],
)
def test_path_traversal_every_binding_form_taints_its_target(
    tmp_path: Path, label: str, binding: str, used: str
) -> None:
    # The invariant: EVERY name bound to a request-sourced value is tainted, not just the first
    # `=`-target on the physical line. Binding only the first one let the real name keep its
    # trusted-constant reading and silenced a genuine traversal.
    (tmp_path / "api.py").write_text(
        _TAINT_HEAD + binding + _TAINT_SINK.format(name=used), encoding="utf-8"
    )
    assert len(PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))) == 1, label


@pytest.mark.parametrize(
    ("label", "body"),
    [
        # THE TRADED-AGAINST DIRECTION. The fix WIDENS which names count as tainted, so its risk is
        # over-tainting: a name bound in a context that is not an assignment must stay trusted, or a
        # legitimate app-internal root starts producing findings.
        ("keyword argument", "helper(path=request.args.get('d'))\n"),
        ("equality comparison", "if CONFIG_SUB == request.args.get('d'):\n    pass\n"),
        ("no request source at all", "CONFIG_SUB = compute_subdir()\n"),
        # The MIRROR of the #444-gate F2 false negative, and a false positive in its own right:
        # a `;` inside a literal used to split the statement, stranding a fragment that reads as
        # a real binding of CONFIG_SUB. Masking in-literal punctuation closes both directions.
        ("assignment quoted inside a literal",
         "msg = 'x;CONFIG_SUB = request.args.get(1)'\n"),
        ("annotation of a DIFFERENT name",
         "OTHER: dict[str, str] = request.args.get('d')\n"),
    ],
)
def test_path_traversal_non_assignment_contexts_do_not_taint(
    tmp_path: Path, label: str, body: str
) -> None:
    (tmp_path / "api.py").write_text(
        _TAINT_HEAD + "CONFIG_SUB = 'cfg'\n" + body
        + "open(os.path.join(BASE_DIR, CONFIG_SUB, 'r.txt')).read()\n",
        encoding="utf-8",
    )
    assert PathTraversalGuard().run(tmp_path, _pyprof(tmp_path)) == [], label


@pytest.mark.parametrize(
    ("label", "sink"),
    [
        ("open", "open(os.path.join(BASE_DIR, SUB)).read()\n"),
        ("send_file", "send_file(os.path.join(BASE_DIR, SUB))\n"),
        ("Path ctor (Rule C)", "Path(os.path.join(BASE_DIR, SUB))\n"),
    ],
)
def test_path_traversal_taint_loss_hit_every_sink_arm(
    tmp_path: Path, label: str, sink: str
) -> None:
    # The #444-gate regressions were in `_tainted_names`, which every sink arm consults, so the
    # loss was not confined to `open(`. One binding that exercises BOTH broken partitions at once
    # (subscripted annotation + a `;` inside a literal), asserted through all three arms.
    (tmp_path / "api.py").write_text(
        "import os\nfrom pathlib import Path\nfrom flask import request, send_file\n"
        "BASE_DIR = '/srv/app'\n"
        "SUB: dict[str, str] = ';'.join(request.args.getlist('d'))\n" + sink,
        encoding="utf-8",
    )
    assert len(PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))) == 1, label


def test_path_traversal_silent_on_nonproduct_path(tmp_path: Path) -> None:
    # Corpus-scan FP: the exact real-world repro was a `scripts/tests/...` path in
    # `tiangolo/full-stack-fastapi-template` — `tests/` is already in the shared
    # `is_nonproduct_path` list, but this guard never called it before this fix.
    d = tmp_path / "scripts" / "tests"
    d.mkdir(parents=True)
    (d / "s.py").write_text(
        "from flask import send_file\ndef d(name):\n    return send_file('/data/' + name)\n", encoding="utf-8"
    )
    assert PathTraversalGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_path_traversal_still_fires_at_a_normal_path(tmp_path: Path) -> None:
    # Direction traded against (CLAUDE.md rule 1): a sibling non-product directory must not
    # silence the same violation shape at an ordinary path.
    d = tmp_path / "scripts" / "tests"
    d.mkdir(parents=True)
    (d / "s.py").write_text(
        "from flask import send_file\ndef d(name):\n    return send_file('/data/' + name)\n", encoding="utf-8"
    )
    (tmp_path / "app.py").write_text(
        "from flask import send_file\ndef d(name):\n    return send_file('/data/' + name)\n", encoding="utf-8"
    )
    findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.location.startswith("app.py") for f in findings)
    assert not any(f.location.startswith("scripts") for f in findings)


# ---------------------------------------------------------------------------
# #676: catastrophic backtracking in _LOOP_TARGET, and the capture bound it needed
# ---------------------------------------------------------------------------

# `[^\n=]*?` contained the space, so it overlapped both neighbouring `\s+` runs and a bare
# `for` followed by a long whitespace run was partitioned combinatorially before the absent
# ` in ` failed. pytest-timeout cannot preempt this hang class (see pyproject.toml), so the
# test asserts the wall clock itself. The window is wide (sub-ms healthy against ~18s broken),
# which is the case an absolute TimingBudget is for (tests/_timing.py).
_C676_BUDGET = register(
    TimingBudget(
        name="path-traversal/loop-target-backtracking",
        seconds=5.0,
        measured=0.0010,
        regression=18.36,
        why="catastrophic for-target backtracking reintroduced (#676)",
    )
)


def test_path_traversal_bare_for_whitespace_line_stays_fast(tmp_path: Path) -> None:
    # The statement must carry a request source, or _tainted_names never reads its head; the
    # head is then `for` + the whitespace run, the #676 pathological shape. The file also
    # carries a KNOWN-firing block so the artifact assertion discriminates (#696 review): a
    # guard that stopped matching entirely would report [] and fail here, instead of passing
    # as "fast and silent".
    (tmp_path / "s.py").write_text(
        "import os\n"
        "def h(request):\n"
        "    for USERFILE in request.args.getlist('f'):\n"
        "        return open(os.path.join('/data', USERFILE)).read()\n"
        + "for" + " " * 4000 + "request.args\n",
        encoding="utf-8",
    )
    start = time.monotonic()
    findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
    elapsed = time.monotonic() - start
    assert [f.rule for f in findings] == ["path-traversal/unsanitized-path"]
    assert_within(elapsed, _C676_BUDGET)


def _caps_target_of_length(n: int) -> str:
    """An ALL-CAPS for-target of exactly `n` chars: a trusted module constant UNLESS tainted."""
    return "U" * n


def _loop_taint_fixture(tmp_path: Path, name: str) -> None:
    (tmp_path / "l.py").write_text(
        "import os\n"
        "def h(request):\n"
        f"    for {name} in request.args.getlist('f'):\n"
        f"        return open(os.path.join('/data', {name})).read()\n",
        encoding="utf-8",
    )


def test_path_traversal_loop_target_taint_still_fires(tmp_path: Path) -> None:
    # Rule 1 still-fires for the #676 narrowing: an ALL-CAPS name bound by a for-target from a
    # request source is tainted, so it must NOT be read as a trusted module constant in the
    # join below. If _LOOP_TARGET stops binding, this goes silent.
    _loop_taint_fixture(tmp_path, "USERFILE")
    findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "path-traversal/unsanitized-path" for f in findings)


def test_path_traversal_loop_target_at_the_bound_still_taints(tmp_path: Path) -> None:
    # Still-taints at the documented limit: `[^\s=]` plus `[^\n=]{0,200}` captures at most 201
    # chars, so a 201-char target is the last one that may be mined, and it must be.
    _loop_taint_fixture(tmp_path, _caps_target_of_length(201))
    findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "path-traversal/unsanitized-path" for f in findings)


def test_path_traversal_loop_target_past_the_bound_is_a_known_limit(tmp_path: Path) -> None:
    # The disclosed cost of the cap, pinned so it cannot drift silently: one char past the
    # limit the target stops being mined, so the ALL-CAPS name reads as a module constant
    # again and the join stays silent. A FALSE NEGATIVE, accepted deliberately: widening the
    # capture back reopens the hang above.
    _loop_taint_fixture(tmp_path, _caps_target_of_length(202))
    assert PathTraversalGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_path_traversal_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string on the flagged line is not a comment; neutral run = control.
    for note in ("# reviewed", "# security: allow-path-traversal"):
        (tmp_path / "s.py").write_text(
            "from flask import send_file\ndef d(name):\n"
            f'    return send_file("/data/" + name, download_name="{note}")\n', encoding="utf-8"
        )
        findings = PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))
        assert [f.rule for f in findings] == ["path-traversal/unsanitized-path"], note


def _llm_path_fixture(assign_tail: str, sink_tail: str) -> str:
    return (
        "from langchain_openai import ChatOpenAI\n"
        "llm = ChatOpenAI()\n"
        "def handle(q):\n"
        f"    response = llm.invoke(q){assign_tail}\n"
        f"    shutil.rmtree(response){sink_tail}\n"
    )


def _llm_path_rules(tmp_path: Path, source: str) -> list[str]:
    (tmp_path / "llmpath.py").write_text(source, encoding="utf-8")
    return [f.rule for f in PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))]


def test_path_traversal_llm_path_pragma_quoted_in_a_string_still_fires(tmp_path: Path) -> None:
    # #1040, both passes of the LLM-output-as-path rule: the pragma quoted in a string on the
    # assignment line or on the sink line is not a comment; neutral run = control.
    for note in ("# reviewed", "# security: allow-path-traversal"):
        for source in (
            _llm_path_fixture(f'; _note = "{note}"', ""),
            _llm_path_fixture("", f'; _note = "{note}"'),
        ):
            assert _llm_path_rules(tmp_path, source) == ["path-traversal/llm-output-as-path"], (note, source)


def test_path_traversal_llm_path_pragma_comment_on_either_line_still_suppresses(tmp_path: Path) -> None:
    # #1040 reach unchanged: a real comment on the assignment line (pass 1) or on the sink line
    # (pass 2) still silences the rule.
    pragma = "  # security: allow-path-traversal"
    assert _llm_path_rules(tmp_path, _llm_path_fixture("", "")) == ["path-traversal/llm-output-as-path"]
    assert _llm_path_rules(tmp_path, _llm_path_fixture(pragma, "")) == []
    assert _llm_path_rules(tmp_path, _llm_path_fixture("", pragma)) == []


# A form feed is a line break to `str.splitlines()` but not to Python; inside a docstring the
# stripper blanks it, so a pragma set numbered on the raw text lands one line low (#1132 review, H1).
_FF_DOCSTRING = f'"""doc{chr(12)}x\nmore"""\n'


def test_path_traversal_pragma_comment_after_a_form_feed_docstring_stays_on_its_own_line(tmp_path: Path) -> None:
    def rules(def_tail: str, sink_tail: str) -> list[str]:
        (tmp_path / "s.py").write_text(
            f"{_FF_DOCSTRING}from flask import send_file\ndef d(name):{def_tail}\n"
            f"    return send_file('/data/' + name){sink_tail}\n", encoding="utf-8"
        )
        return [f.rule for f in PathTraversalGuard().run(tmp_path, _pyprof(tmp_path))]

    pragma = "  # security: allow-path-traversal"
    assert rules("", "") == ["path-traversal/unsanitized-path"]  # control
    assert rules("", pragma) == []
    # The other direction: the pragma on the line ABOVE the sink must not silence it.
    assert rules(pragma, "") == ["path-traversal/unsanitized-path"]
    # Pass 1 of the LLM rule reads the same set: the assignment line's comment still reaches.
    (tmp_path / "s.py").unlink()
    assert _llm_path_rules(tmp_path, _FF_DOCSTRING + _llm_path_fixture("", "")) == ["path-traversal/llm-output-as-path"]
    assert _llm_path_rules(tmp_path, _FF_DOCSTRING + _llm_path_fixture(pragma, "")) == []
