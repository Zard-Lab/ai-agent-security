from __future__ import annotations

from agentsec.findings import _is_review_finding
from agentsec.guards.ssrf_general import SsrfGeneralGuard
from tests.guards._common import *  # noqa: F401,F403


def test_ssrf_general_flags_fstring_url(tmp_path: Path) -> None:
    (tmp_path / "f.py").write_text("import requests\ndef get(host):\n    return requests.get(f'https://{host}/x')\n", encoding="utf-8")
    findings = SsrfGeneralGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/user-controlled-url"
    assert findings[0].severity == "high"

def test_ssrf_general_flags_request_derived_urlopen(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "from urllib.request import urlopen\ndef f(request):\n    return urlopen(request.args['u'])\n", encoding="utf-8"
    )
    assert len(SsrfGeneralGuard().run(tmp_path, _pyprof(tmp_path))) == 1

def test_ssrf_general_passes_static_literal(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text("import requests\ndef f():\n    return requests.get('https://api.example.com/v1')\n", encoding="utf-8")
    assert SsrfGeneralGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_ssrf_general_passes_bare_variable(tmp_path: Path) -> None:
    # conservative by design: a bare variable with no user/dynamic signal does NOT fire
    (tmp_path / "t.py").write_text("import requests\nURL = settings.UPSTREAM\ndef f():\n    return requests.get(URL)\n", encoding="utf-8")
    assert SsrfGeneralGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_ssrf_general_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import requests\ndef f(host):\n    return requests.get(f'https://{host}/x')  # security: allow-ssrf\n", encoding="utf-8"
    )
    assert SsrfGeneralGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_ssrf_general_silent_on_trailing_comment_after_bare_arg(tmp_path: Path) -> None:
    # #423 FP-bait: a bare-variable URL is not flagged; a trailing same-line comment mentioning
    # `request.` must not leak into the arg and trip the user-signal check.
    (tmp_path / "f.py").write_text(
        "import requests\n"
        "def get(url):\n"
        "    return requests.get(url)  # forwards request.headers downstream\n",
        encoding="utf-8",
    )
    assert SsrfGeneralGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_ssrf_general_na_without_python() -> None:
    assert SsrfGeneralGuard().applies(mkprofile(Path("/tmp"), features={"frontend"})) is False


# --- #861: host-source-aware classification ------------------------------------------------
# The taint decision moved from "is the URL dynamic?" to "is the *destination host*
# attacker-influenced?". A config/self/constant host is downgraded to a MEDIUM surfacing
# finding (SSRF-via-config review signal); a literal host with only a path segment interpolated
# is silent (not SSRF). Both directions are tested here per Review Doctrine Rule 1: every
# narrowing carries a test that the vulnerable direction STILL fires HIGH.

def _run(tmp_path: Path, code: str) -> list:
    (tmp_path / "c.py").write_text(code, encoding="utf-8")
    return SsrfGeneralGuard().run(tmp_path, _pyprof(tmp_path))


def test_ssrf_general_downgrades_self_attr_config_host(tmp_path: Path) -> None:
    # narrowing: host = a `self.<attr>` sourced from operator config (the 7 forgejo FPs) ->
    # MEDIUM surfacing, not gating HIGH. Still SURFACED, not suppressed (SSRF-via-config).
    findings = _run(
        tmp_path,
        "import os\nimport requests\n"
        "class Client:\n"
        "    def __init__(self):\n"
        "        self.api_url = os.environ['FORGEJO_URL']\n"
        "    def repo(self, owner, name):\n"
        "        return requests.get(f'{self.api_url}/repos/{owner}/{name}')\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/config-host-fetch"
    assert findings[0].severity == "medium"

def test_ssrf_general_downgrades_module_constant_host(tmp_path: Path) -> None:
    # narrowing: host = an ALL-CAPS module constant -> MEDIUM surfacing.
    findings = _run(
        tmp_path,
        "import requests\nBASE = 'https://api.internal'\n"
        "def f(name):\n    return requests.get(f'{BASE}/repos/{name}')\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/config-host-fetch"
    assert findings[0].severity == "medium"

def test_ssrf_general_downgrades_settings_attr_host(tmp_path: Path) -> None:
    # narrowing: host = a `settings.` config attribute -> MEDIUM surfacing.
    findings = _run(
        tmp_path,
        "import requests\nfrom app import settings\n"
        "def f(path):\n    return requests.get(f'{settings.UPSTREAM}/{path}')\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/config-host-fetch"
    assert findings[0].severity == "medium"

def test_ssrf_general_silent_on_literal_host_path_only(tmp_path: Path) -> None:
    # narrowing (decision-free): a fixed literal host with only a PATH segment interpolated is
    # not SSRF under any threat model -> fully silent.
    assert _run(
        tmp_path,
        "import requests\ndef f(name):\n    return requests.get(f'https://api.example.com/repos/{name}')\n",
    ) == []

def test_ssrf_general_silent_on_static_fstring(tmp_path: Path) -> None:
    # narrowing bonus: an f-string with NO interpolation is a static literal, not user input.
    assert _run(
        tmp_path,
        "import requests\ndef f():\n    return requests.get(f'https://api.example.com/v1')\n",
    ) == []

def test_ssrf_general_still_high_on_request_host(tmp_path: Path) -> None:
    # direction traded against — MUST still fire HIGH: a genuine request-sourced host.
    findings = _run(
        tmp_path,
        "import requests\ndef f(request):\n    return requests.get(f\"https://{request.args['host']}/x\")\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/user-controlled-url"
    assert findings[0].severity == "high"


def test_ssrf_general_config_host_is_a_review_signal_and_user_url_is_proven(tmp_path: Path) -> None:
    # #766: the `surfacing_rule_prefixes` declaration had no behavioral pin, so emptying it left the
    # suite green. Both directions in one run, so a prefix widened to `ssrf-general/` fails too.
    findings = _run(
        tmp_path,
        "import requests\nBASE = 'https://api.internal'\n"
        "def f(name):\n    return requests.get(f'{BASE}/repos/{name}')\n"
        "def g(request):\n    return requests.get(f\"https://{request.args['host']}/x\")\n",
    )
    assert {(f.rule, _is_review_finding(f)) for f in findings} == {
        ("ssrf-general/config-host-fetch", True),
        ("ssrf-general/user-controlled-url", False),
    }

def test_ssrf_general_still_high_on_concat_request_host(tmp_path: Path) -> None:
    # direction traded against — MUST still fire HIGH: request input concatenated into the host.
    findings = _run(
        tmp_path,
        "import requests\ndef f(request):\n    return requests.get('https://' + request.args['h'] + '/x')\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/user-controlled-url"
    assert findings[0].severity == "high"

def test_ssrf_general_still_high_on_bare_param_host(tmp_path: Path) -> None:
    # direction traded against — MUST still fire HIGH: a bare-parameter host (the canary shape,
    # and RCA FP #9 `f'{endpoint}/count'`, deliberately scoped IN as the conservative cost —
    # no intra-file heuristic can distinguish it from the canary).
    findings = _run(
        tmp_path,
        "import requests\ndef get_triple_count(endpoint: str):\n    return requests.get(f'{endpoint}/count')\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/user-controlled-url"
    assert findings[0].severity == "high"

def test_ssrf_general_anti_bypass_tainted_constant_looking_host(tmp_path: Path) -> None:
    # anti-bypass (Review Doctrine Rule 1): an ALL-CAPS name looks like a module constant, but
    # this file bound it from a request source — it must NOT be laundered into the config
    # downgrade; it stays HIGH.
    findings = _run(
        tmp_path,
        "import requests\ndef f(request):\n    HOST = request.args['u']\n    return requests.get(f'{HOST}/y')\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/user-controlled-url"
    assert findings[0].severity == "high"


# --- #868: compound-host authority (more than one interpolation before the first `/`) --------
# Regression: `_fstring_host_class` classified from only the FIRST interpolation, so a config
# prefix short-circuited the whole authority and an attacker-controllable later segment was
# silently downgraded from gating HIGH to non-gating MEDIUM. Every interpolation in the host
# authority span is now classified. Both directions per Review Doctrine Rule 1.

def test_ssrf_general_compound_host_bare_param_segment_is_high(tmp_path: Path) -> None:
    # direction traded against — MUST fire HIGH: a config prefix (`{self.env}`) does not launder
    # a bare-param subdomain (`{tenant}`) in the SAME authority. Fails against the pre-#868 code
    # (which returned MEDIUM off the first interpolation only).
    findings = _run(
        tmp_path,
        "import requests\n"
        "class C:\n"
        "    def f(self, tenant):\n"
        "        return requests.get(f'https://{self.env}-{tenant}.internal.example.com/x')\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/user-controlled-url"
    assert findings[0].severity == "high"

def test_ssrf_general_compound_host_tainted_segment_is_high(tmp_path: Path) -> None:
    # anti-bypass: the `_tainted_names` check must reach a LATER interpolation, not only the
    # first. A request-bound `tenant` in a compound authority stays HIGH.
    findings = _run(
        tmp_path,
        "import requests\n"
        "class C:\n"
        "    def f(self, request):\n"
        "        tenant = request.args['t']\n"
        "        return requests.get(f'https://{self.env}-{tenant}.internal.example.com/x')\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/user-controlled-url"
    assert findings[0].severity == "high"

def test_ssrf_general_compound_host_all_config_stays_medium(tmp_path: Path) -> None:
    # direction changed — MUST stay MEDIUM (do not over-widen): every interpolation in the
    # authority is operator config, so this remains the config-host surfacing finding.
    findings = _run(
        tmp_path,
        "import requests\n"
        "class C:\n"
        "    def f(self):\n"
        "        return requests.get(f'https://{self.env}-{self.region}.internal.example.com/x')\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/config-host-fetch"
    assert findings[0].severity == "medium"

def test_ssrf_general_compound_host_separator_inside_interp_is_high(tmp_path: Path) -> None:
    # FP-bait for the authority walk: a `/` INSIDE an interpolation must not end the host span
    # early (which would drop the `{tenant}` segment). The bare-param host stays HIGH.
    findings = _run(
        tmp_path,
        "import requests\n"
        "def f(tenant, pick):\n"
        "    return requests.get(f\"https://{pick('/a')}-{tenant}.svc/x\")\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/user-controlled-url"
    assert findings[0].severity == "high"


# --- #868 follow-up: the authority is host+port+userinfo, not just the host label -----------
# The "classify every interpolation in the authority" rule (#868) means a user-controlled PORT on
# an otherwise-config host is an attacker-influenced destination and escalates to HIGH. This is an
# intentional, accepted behaviour (a bare port is a genuine internal-port-scan primitive, and it
# matches the guard's bare-param-is-user default). Locked in both directions so it cannot silently
# flip back to MEDIUM, and so the escalation stays scoped to the BARE (non-config) case.

def test_ssrf_general_bare_port_on_config_host_is_high(tmp_path: Path) -> None:
    # narrowing traded against — a bare local `port` in the authority of a config host escalates
    # the whole finding to gating HIGH (the attacker can redirect to another service/port).
    findings = _run(
        tmp_path,
        "import requests\n"
        "class C:\n"
        "    def f(self, port):\n"
        "        return requests.get(f'https://{self.host}:{port}/x')\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/user-controlled-url"
    assert findings[0].severity == "high"

def test_ssrf_general_config_port_on_config_host_stays_medium(tmp_path: Path) -> None:
    # FP-bait / scope guard — a CONFIG port (`self.port`) on a config host must NOT escalate: the
    # whole authority is operator config, so it stays the MEDIUM surfacing finding.
    findings = _run(
        tmp_path,
        "import requests\n"
        "class C:\n"
        "    def f(self):\n"
        "        return requests.get(f'https://{self.host}:{self.port}/x')\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/config-host-fetch"
    assert findings[0].severity == "medium"


# --- #878: config-host trace through a hoisted local or a string method ----------------------
# #861 demoted a config host to MEDIUM only when the config symbol stood BARE in the f-string at
# the fetch site. If the URL was hoisted into a local (`url = f"{self.api_url}/x"; get(url.format(
# ...))`) or a string method was applied to the host (`f"{self.api_url.rstrip('/')}/v"`), the
# config trace was lost and it fell back to gating HIGH. The fix follows the host source through a
# same-block local resolution and a trailing string-method peel, and widens the config vocabulary
# to a leading-underscore private constant (`_API_URL`). Every case is a strict DOWNGRADE, so both
# directions are tested per Review Doctrine Rule 1: the FP-bait (a genuinely user-controlled local
# staying HIGH) is the load-bearing half.

def test_ssrf_general_878_hoisted_local_format_downgrades(tmp_path: Path) -> None:
    # widening: a URL hoisted into a local and `.format`-ted at the fetch site resolves to its
    # config-derived f-string assignment -> MEDIUM (the forgejo `url.format(path=path)` shape).
    findings = _run(
        tmp_path,
        "import os, requests\n"
        "class Client:\n"
        "    def __init__(self):\n"
        "        self.api_url = os.environ['FORGEJO_URL']\n"
        "    def repo(self, path):\n"
        "        url = f'{self.api_url}/repos/x/{{path}}'\n"
        "        return requests.get(url.format(path=path))\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/config-host-fetch"
    assert findings[0].severity == "medium"

def test_ssrf_general_878_string_method_on_self_attr_downgrades(tmp_path: Path) -> None:
    # widening: a trailing `.rstrip('/')` on a `self.` config attr is peeled -> MEDIUM.
    findings = _run(
        tmp_path,
        "import requests\n"
        "class C:\n"
        "    def __init__(self):\n"
        "        self.api_url = os.environ['U']\n"
        "    def v(self):\n"
        "        return requests.get(f\"{self.api_url.rstrip('/')}/v\")\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/config-host-fetch"
    assert findings[0].severity == "medium"

def test_ssrf_general_878_string_method_on_underscore_constant_downgrades(tmp_path: Path) -> None:
    # widening: exercises all three fix parts at once (the `test_publish_integration.py:61` shape):
    # a leading-underscore module constant + a `.rstrip('/')` string method -> MEDIUM.
    findings = _run(
        tmp_path,
        "import os, requests\n"
        "_API_URL = os.environ['API_URL']\n"
        "def ver():\n"
        "    return requests.get(f\"{_API_URL.rstrip('/')}/version\")\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/config-host-fetch"
    assert findings[0].severity == "medium"

def test_ssrf_general_878_bare_underscore_constant_host_downgrades(tmp_path: Path) -> None:
    # widening (locks the leading-underscore vocabulary independently of the peel): a bare
    # `_API_URL` host with no method must classify as config, exactly like `API_URL`.
    findings = _run(
        tmp_path,
        "import os, requests\n_API_URL = os.environ['U']\n"
        "def f(n):\n    return requests.get(f'{_API_URL}/{n}')\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/config-host-fetch"
    assert findings[0].severity == "medium"

def test_ssrf_general_878_resolved_local_only_downgrades_to_config(tmp_path: Path) -> None:
    # scope guard (#881 review, Fix B): resolution may ONLY downgrade HIGH -> MEDIUM when the
    # resolved host is config; it never silences. A hoisted local whose RHS is not clearly a config
    # host (here a literal-host f-string that _url_host_class returns None for) keeps the
    # conservative HIGH -- matching origin/main's `.format` behavior. Silencing it would risk
    # dropping a plain-string `.format` host template we cannot parse (see the CRITICAL repro below).
    findings = _run(
        tmp_path,
        "import requests\n"
        "def f(path):\n"
        "    url = f'https://api.example.com/{{path}}'\n"
        "    return requests.get(url.format(path=path))\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/user-controlled-url"
    assert findings[0].severity == "high"

def test_ssrf_general_878_tainted_format_argument_stays_high(tmp_path: Path) -> None:
    # direction traded against -- LOAD-BEARING (#881 review, Critical): request input injected into
    # the URL through a `.format` ARGUMENT (`url.format(host=request.args[...])`) must NOT be peeled
    # away and laundered. Taint-first over the FULL arg keeps it gating HIGH. This shape returned []
    # (silenced!) before the fix -- a genuine SSRF turned invisible.
    findings = _run(
        tmp_path,
        "import requests\n"
        "def fetch(request):\n"
        "    url = 'http://{host}/path'\n"
        "    return requests.get(url.format(host=request.args['h']))\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/user-controlled-url"
    assert findings[0].severity == "high"

def test_ssrf_general_878_tainted_local_in_format_argument_stays_high(tmp_path: Path) -> None:
    # direction traded against (#881 review, Critical, variant): the taint reaches the `.format`
    # argument through a tainted local, not a literal `request.` at the sink. The full-arg tainted-
    # token check catches it -> HIGH. Also returned [] before the fix.
    findings = _run(
        tmp_path,
        "import requests\n"
        "def fetch(request):\n"
        "    h = request.args['h']\n"
        "    url = 'http://{host}/path'\n"
        "    return requests.get(url.format(host=h))\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/user-controlled-url"
    assert findings[0].severity == "high"

def test_ssrf_general_878_sibling_method_local_not_borrowed_tainted(tmp_path: Path) -> None:
    # direction traded against (#881 review, High): a same-named `url` in a SIBLING method must not
    # be borrowed to launder a tainted fetch. The tainted `.format` argument keeps it HIGH; this
    # returned MEDIUM (laundered) before the fix.
    findings = _run(
        tmp_path,
        "import requests\n"
        "class C:\n"
        "    def __init__(self):\n"
        "        self.other_config = 'https://cfg.example.com'\n"
        "    def other(self):\n"
        "        url = f'{self.other_config}/x'\n"
        "    def fetch(self, request):\n"
        "        return requests.get(url.format(host=request.args['h']))\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/user-controlled-url"
    assert findings[0].severity == "high"

def test_ssrf_general_878_sibling_method_local_not_borrowed_untainted(tmp_path: Path) -> None:
    # FP-bait for _same_block (#881 review, Fix C, discriminating even without any taint): a `url`
    # assigned in a sibling method (indented `def`, not column 0) must not be treated as this
    # method's local -- in real Python `url` is undefined here. It stays the conservative HIGH
    # rather than being misattributed to the sibling's config assignment (MEDIUM before Fix C).
    findings = _run(
        tmp_path,
        "import requests\n"
        "class C:\n"
        "    def __init__(self):\n"
        "        self.other_config = 'https://cfg.example.com'\n"
        "    def other(self):\n"
        "        url = f'{self.other_config}/{{path}}'\n"
        "    def fetch(self, path):\n"
        "        return requests.get(url.format(path=path))\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/user-controlled-url"
    assert findings[0].severity == "high"

def test_ssrf_general_878_tainted_local_stays_high(tmp_path: Path) -> None:
    # direction traded against — LOAD-BEARING: the hoisted local is bound from request data, so it
    # must NOT be laundered into the config downgrade. Taint-first keeps it gating HIGH.
    findings = _run(
        tmp_path,
        "import requests\n"
        "def f(request):\n"
        "    url = f\"https://{request.headers['x-host']}/x\"\n"
        "    return requests.get(url.format(a=1))\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/user-controlled-url"
    assert findings[0].severity == "high"

def test_ssrf_general_878_request_arg_local_stays_high(tmp_path: Path) -> None:
    # direction traded against: a local assigned straight from `request.args` then `.format`-ted
    # stays HIGH (the local is tainted).
    findings = _run(
        tmp_path,
        "import requests\n"
        "def f(request):\n"
        "    url = request.args['u']\n"
        "    return requests.get(url.format())\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/user-controlled-url"
    assert findings[0].severity == "high"

def test_ssrf_general_878_unresolvable_local_stays_high(tmp_path: Path) -> None:
    # direction traded against: the local is assigned in ANOTHER function (not the same block), so
    # it cannot be resolved and the conservative HIGH is kept (no cross-function laundering).
    findings = _run(
        tmp_path,
        "import requests\n"
        "def other():\n"
        "    url = f'{SETTINGS}/x'\n"
        "def fetch(p):\n"
        "    return requests.get(url.format(path=p))\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/user-controlled-url"
    assert findings[0].severity == "high"

def test_ssrf_general_878_bare_param_local_no_signal_stays_silent(tmp_path: Path) -> None:
    # scope guard: a bare local whole-URL fetch with NO method/concat signal stays silent even
    # though its assignment is a bare-param f-string — resolution only DOWNGRADES an already-HIGH
    # line, it never upgrades a "too noisy" bare variable into a new finding.
    assert _run(
        tmp_path,
        "import requests\n"
        "def f(host):\n"
        "    url = f'https://{host}/x'\n"
        "    return requests.get(url)\n",
    ) == []

def test_ssrf_general_878_replace_method_on_config_host_downgrades(tmp_path: Path) -> None:
    # widening: a `.replace(...)` string method over a `self.` config attr is peeled (its arg
    # literals are masked, so the `/`/`:` inside them don't confuse the scan) -> MEDIUM.
    findings = _run(
        tmp_path,
        "import requests\n"
        "class C:\n"
        "    def __init__(self):\n"
        "        self.api_url = os.environ['U']\n"
        "    def v(self):\n"
        "        return requests.get(f\"{self.api_url.replace('http://', 'https://')}/v\")\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/config-host-fetch"
    assert findings[0].severity == "medium"


# --- #881 fresh-eyes review: multi-assignment (branch) local resolution ----------------------
# Resolution classifies the local's assignment(s), not just one. When the same local is reassigned
# across mutually-exclusive branches, the downgrade to MEDIUM is only sound if EVERY branch is a
# config host; a single attacker-controlled branch must keep the gating HIGH. Classifying only the
# textually-last assignment (the pre-fix `max()`) laundered a user branch to MEDIUM. Both
# directions per Review Doctrine Rule 1 -- the mixed-branch FP-bait is the load-bearing half.

def test_ssrf_general_881_mixed_branch_reassignment_stays_high(tmp_path: Path) -> None:
    # direction traded against -- LOAD-BEARING (#881 fresh-eyes review, Critical): a bare-param host
    # in the first branch (`url = f'{host}/x'`) is attacker-controlled, so even though a later
    # branch reassigns `url` to a config host, the fetch must stay gating HIGH. The guard's own
    # `test_ssrf_general_still_high_on_bare_param_host` establishes a bare-parameter host is
    # attacker-controlled; this path must not silently defeat it. Returned config-host-fetch MEDIUM
    # (laundered) before the fix -- so this test discriminates the `all()` fix from the `max()` bug.
    findings = _run(
        tmp_path,
        "import os, requests\n"
        "class C:\n"
        "    def __init__(self):\n"
        "        self.api_url = os.environ['U']\n"
        "    def fetch(self, host=None):\n"
        "        url = f'{host}/x'\n"
        "        if not host:\n"
        "            url = f'{self.api_url}/x'\n"
        "        return requests.get(url.format())\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/user-controlled-url"
    assert findings[0].severity == "high"

def test_ssrf_general_881_all_config_branches_stay_medium(tmp_path: Path) -> None:
    # widening's benign neighbour (#881 fresh-eyes review): when EVERY same-block assignment is a
    # config host, the local still correctly downgrades to MEDIUM -- the `all()` fix keeps the #878
    # downgrade for legitimately config-only locals and is not over-conservative.
    findings = _run(
        tmp_path,
        "import os, requests\n"
        "class C:\n"
        "    def __init__(self):\n"
        "        self.api_url = os.environ['U']\n"
        "        self.backup_url = os.environ['B']\n"
        "    def fetch(self, primary=True):\n"
        "        url = f'{self.api_url}/x'\n"
        "        if not primary:\n"
        "            url = f'{self.backup_url}/x'\n"
        "        return requests.get(url.format())\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/config-host-fetch"
    assert findings[0].severity == "medium"


# --- #869: the authority PREFIX — interpolated scheme, protocol-relative `//`, escaped braces ---
# `_fstring_host_class` located the authority with three independent approximations: a literal-only
# scheme regex to find where it STARTS, a symmetric brace walk to find where it ENDS, and a
# non-escape-aware `{...}` regex to pull the interpolations out. Three boundary shapes mis-parsed:
# an interpolated scheme (`f"{self.scheme}://{tenant}.svc/x"`) stopped the walk at the `/` of its
# own `://`, so `{tenant}` was never classified (a gating HIGH silently downgraded to non-gating
# MEDIUM — a failure that presents as success); a protocol-relative `//` ended the authority at
# index 0 (no finding at all); and an escaped `{{literal}}` was read as a real interpolation
# (spurious HIGH on a fixed literal host). One escape-aware tokenizer now decides both "what is an
# interpolation" and "where does the authority start". Gaps 1–2 are a WIDENING: the vulnerable
# case must fire AND the config neighbour must stay MEDIUM / the literal neighbour silent. Gap 3 is
# a NARROWING: the FP goes silent AND the legal triple-brace `{{{tenant}}}` (a literal `{`, a real
# interpolation, a literal `}`) must STILL fire HIGH — the load-bearing half. Rule 1, both ways.

def test_ssrf_general_869_interp_scheme_bare_host_is_high(tmp_path: Path) -> None:
    # widening — MUST fire HIGH: an interpolated (config) scheme does not stop the authority walk
    # at its own `://`; the bare-param host `{tenant}` after it is reached and classifies user.
    # Returned MEDIUM before the fix (only `self.scheme` was classified) — a real SSRF passing CI.
    findings = _run(
        tmp_path,
        "import httpx\n"
        "class C:\n"
        "    async def go(self, tenant):\n"
        "        return await httpx.get(f'{self.scheme}://{tenant}.svc/x')\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/user-controlled-url"
    assert findings[0].severity == "high"

def test_ssrf_general_869_interp_scheme_all_config_stays_medium(tmp_path: Path) -> None:
    # FP-bait for the widening — MUST stay MEDIUM: an interpolated scheme is CLASSIFIED as part of
    # the destination (scheme+host), not blanket-HIGH. An all-config authority (`self.scheme` +
    # `self.host`) is the config-host surfacing finding, exactly like `f"https://{self.host}/x"`.
    findings = _run(
        tmp_path,
        "import httpx\n"
        "class C:\n"
        "    async def go(self):\n"
        "        return await httpx.get(f'{self.scheme}://{self.host}/x')\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/config-host-fetch"
    assert findings[0].severity == "medium"

def test_ssrf_general_869_protocol_relative_bare_host_is_high(tmp_path: Path) -> None:
    # widening — MUST fire HIGH: a protocol-relative `//` prefix is an authority MARKER (like
    # `scheme://`), not the end of the authority. Returned [] (a silent miss) before the fix.
    findings = _run(
        tmp_path,
        "import requests\n"
        "def f(tenant):\n"
        "    return requests.get(f'//{tenant}.svc/x')\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/user-controlled-url"
    assert findings[0].severity == "high"

def test_ssrf_general_869_protocol_relative_config_host_stays_medium(tmp_path: Path) -> None:
    # FP-bait for the widening — MUST stay MEDIUM: the `//` prefix only relocates where the
    # authority starts; a config host behind it is still the config-host surfacing finding.
    findings = _run(
        tmp_path,
        "import requests\n"
        "class C:\n"
        "    def f(self):\n"
        "        return requests.get(f'//{self.host}/x')\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/config-host-fetch"
    assert findings[0].severity == "medium"

def test_ssrf_general_869_protocol_relative_literal_host_silent(tmp_path: Path) -> None:
    # FP-bait for the widening — MUST stay silent: a protocol-relative URL on a fixed literal host
    # with only a path segment interpolated is not SSRF (same rule as `https://cdn.example.com/{p}`).
    assert _run(
        tmp_path,
        "import requests\ndef f(p):\n    return requests.get(f'//cdn.example.com/{p}')\n",
    ) == []

def test_ssrf_general_869_single_slash_relative_path_silent(tmp_path: Path) -> None:
    # scope guard — MUST stay silent: a SINGLE leading `/` is a relative path, not a protocol-
    # relative authority. The `//` handling must not widen to it (the destination is the current
    # origin; `{tenant}` is a path segment).
    assert _run(
        tmp_path,
        "import requests\ndef f(tenant):\n    return requests.get(f'/{tenant}/x')\n",
    ) == []

def test_ssrf_general_869_escaped_braces_in_host_silent(tmp_path: Path) -> None:
    # narrowing — MUST go silent: `{{`/`}}` are Python's escaped LITERAL braces, so the string is
    # `https://{literal}.example.com/x` — a fixed literal host with no interpolation at all.
    # Returned HIGH before the fix (the inner `{literal}` was read as a real interpolation).
    assert _run(
        tmp_path,
        "import requests\ndef f():\n    return requests.get(f'https://{{literal}}.example.com/x')\n",
    ) == []

def test_ssrf_general_869_escaped_only_fstring_silent(tmp_path: Path) -> None:
    # narrowing — MUST go silent: an f-string whose ONLY braces are escapes is a static literal
    # (the same outcome as `test_ssrf_general_silent_on_static_fstring`). Returned HIGH before.
    assert _run(
        tmp_path,
        "import requests\ndef f():\n    return requests.get(f'https://{{x}}.example.com/{{y}}')\n",
    ) == []

def test_ssrf_general_869_triple_brace_interp_host_still_high(tmp_path: Path) -> None:
    # direction traded against — LOAD-BEARING: `{{{tenant}}}` is a literal `{`, a REAL
    # interpolation `{tenant}`, then a literal `}`. The escape handling must not swallow the real
    # interpolation (a naive leftmost `}}` replace eats its closing brace and silences a genuine
    # bare-param host). Stays gating HIGH.
    findings = _run(
        tmp_path,
        "import requests\ndef f(tenant):\n    return requests.get(f'https://{{{tenant}}}.svc/x')\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/user-controlled-url"
    assert findings[0].severity == "high"

def test_ssrf_general_869_unterminated_brace_degrades_to_high(tmp_path: Path) -> None:
    # scope guard for the tokenizer's failure mode: an unterminated `{` (not valid Python, but the
    # body regex can hand the guard one from an odd quoting shape) is treated as ONE interpolation
    # running to the end of the body — a bare identifier in it classifies user, so the guard
    # degrades to the conservative HIGH rather than to silence.
    findings = _run(
        tmp_path,
        "import requests\ndef f(host):\n    return requests.get(f'https://{host/x')\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-general/user-controlled-url"
    assert findings[0].severity == "high"


def test_ssrf_general_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string on the fetch line is not a comment; neutral run = control.
    for note in ("# reviewed", "# security: allow-ssrf"):
        findings = _run(
            tmp_path,
            f"import requests\ndef f(host):\n    return requests.get(f'https://{{host}}/x'); _note = \"{note}\"\n",
        )
        assert [f.rule for f in findings] == ["ssrf-general/user-controlled-url"], note


def test_ssrf_general_pragma_quoted_in_a_string_on_a_hoisted_assignment_changes_nothing(tmp_path: Path) -> None:
    # #1040: the hoist resolver skips an assignment line whose pragma is a real comment; the phrase
    # quoted in a string there no longer counts, so the fetch reads exactly as its neutral control.
    for note in ("# reviewed", "# security: allow-ssrf"):
        findings = _run(
            tmp_path,
            "import os, requests\n"
            "class Client:\n"
            "    def __init__(self):\n"
            "        self.api_url = os.environ['FORGEJO_URL']\n"
            "    def repo(self, path):\n"
            f"        url = f'{{self.api_url}}/repos/x/{{{{path}}}}'; _note = \"{note}\"\n"
            "        return requests.get(url.format(path=path))\n",
        )
        assert [(f.rule, f.severity) for f in findings] == [("ssrf-general/config-host-fetch", "medium")], note


def test_ssrf_general_pragma_comment_on_a_hoisted_assignment_drops_it_from_the_resolver(tmp_path: Path) -> None:
    # #1040 reach, the direction the string test above cannot see (#1132 review, L1): a real
    # comment on the assignment line still removes it from the hoist resolver, so the fetch no
    # longer resolves to its config host and reads as user-controlled.
    findings = _run(
        tmp_path,
        "import os, requests\n"
        "class Client:\n"
        "    def __init__(self):\n"
        "        self.api_url = os.environ['FORGEJO_URL']\n"
        "    def repo(self, path):\n"
        "        url = f'{self.api_url}/repos/x/{{path}}'  # security: allow-ssrf\n"
        "        return requests.get(url.format(path=path))\n",
    )
    assert [(f.rule, f.severity) for f in findings] == [("ssrf-general/user-controlled-url", "high")]
