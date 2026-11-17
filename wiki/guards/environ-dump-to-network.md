---
type: Guard
title: "environ-dump-to-network"
description: "No code serializes the whole process environment and sends it to a network sink, or exfiltrates environment/credential-store content via a Telegram bot or Discord webhook."
timestamp: "2026-10-24T00:00:00Z"
guard_id: "environ-dump-to-network"
checklist_section: ["8"]
standards: ["OWASP:A08", "CWE-200"]
---

# No code serializes the whole process environment and sends it to a network sink

_Author — 2026-10-18_

---

## The threat

Environment variables routinely hold CI tokens, cloud credentials, and API keys. Code that
serializes the ENTIRE environment and sends it anywhere over the network is a credential-
stealer, not a diagnostic helper (MITRE ATT&CK T1552.001, Credentials in Files; T1041,
Exfiltration Over C2 Channel).

WHO reaches this: any package install, AI-agent skill, or contribution that ships this code.
WHAT privilege / TO WHAT EFFECT: every secret the process's environment holds, exfiltrated in
one shot. Standards: OWASP:A08 (Software and Data Integrity Failures), CWE-200 (Exposure of
Sensitive Information to an Unauthorized Actor).

## Why it's often introduced / why no existing agentsec guard covers this

`env_secret_logged.py`/`env_secret_console_log.py`/`env_secret_in_prompt.py` cover a secret
reaching a LOG or an LLM PROMPT — a different sink entirely from a direct network send.
`dns_exfiltration_pattern.py` covers DNS-channel exfiltration specifically (a dynamically-built
hostname, or an OOB-beacon domain) — not HTTP/SMTP sends of a serialized environment. Confirmed
by grepping every guard for a network-sink-plus-environ-dump shape before building this one;
none existed.

## Detection design

Ported from `rakshit-737/warden-supply-chain-security`'s `warden-python.yml` semgrep rule
(`warden.credential_access.environ-dump-to-network`) and `warden_exfiltration.yar`'s Telegram/
Discord rules (fetched and read in full).

**`environ-dump-network-sink` (CRITICAL).**

1. **`applies()` gate:** `{"python", "javascript", "typescript"} & profile.features`.
2. **Files scanned:** `.py`/`.js`/`.ts`/`.jsx`/`.tsx`/`.mjs`/`.cjs`, `is_nonproduct_path`
   filtered.
3. **Pattern:** the WHOLE `os.environ` serialized (`json.dumps(dict(os.environ))`,
   `str(os.environ)`/`repr(os.environ)`, or a dict comprehension over `os.environ.items()`),
   and that dump REACHES a network-send call (`requests.post/put/request`, `httpx.post/put`,
   `urllib`'s `urlopen`/`Request`, or `smtplib`'s `sendmail`). Reading one named variable
   (`os.environ["API_KEY"]`, `os.environ.get(...)`) is ordinary configuration and does not
   match.
4. **"Reaches" means one of two links, never mere co-occurrence in the file:**
   - **Inline:** the dump is itself in the send call's argument list. A bare copy
     (`dict(os.environ)`, `os.environ.copy()`, `dict(os.environ.items())`) counts only here, as
     the call's own argument (`requests.post(url, json=os.environ.copy())`), because a copy is
     also exactly what a subprocess `env=` takes.
   - **By name:** a variable assigned by the dump's statement is a VALUE in the call's argument
     list. Every dump in the file is a source. The statement may span lines, so a dump nested
     in a multi-line dict literal assigns the dict's variable. Up to three further assignments
     are followed (`d = json.dumps(...)`, then `body = d.encode()`, then
     `requests.post(url, data=body)`). A typed assignment (`payload: str = ...`) counts. A keyword
     NAME (`data=`), a word inside a plain string literal (a dict key `{"payload": ...}`, a URL
     path `"/data"`), and an attribute name (`resp.data`) are not references to a variable of
     that name; a keyword's value, an f-string interpolation (`f"{payload}"`) and a bare name in
     an expression (`"env=" + d`, `d.encode()`) are.

   The by-name link reads the file through Python's own tokenizer (`_code_view`): only NAME,
   NUMBER and OP tokens are code, and string and f-string text, format specs, prefixes, quotes,
   comments and docstrings are blank. An f-string's `{...}` expressions arrive as ordinary
   tokens, so `f"{payload}"` links while a key inside one (`f"{row['data']}"`,
   `f"{cfg["payload"]}"`), a doubled `{{payload}}` brace or a spec (`{color:#x}`) never does.
   Statements are the tokenizer's logical lines, so a statement runs on through a triple-quoted
   template (`msg = f"""...{p}..."""`) and its `""".format(payload)` closing line. PR #1093
   rounds 3 to 5 hand-rolled this reading three times, and each version disagreed with Python
   somewhere (a prefixed literal's closing quote, PEP 701 same-quote nesting, a `#` in a format
   spec); round 6 made the tokenizer, which had been the test oracle, the implementation.
   Indentation is never tokenized (lines are de-indented, columns mapped back), so a Python 2
   tab/space mix still links. Any other tokenizer failure keeps only the inline check, on the
   stripped text, as the first tokenizer version (round 6) did; the earlier hand-rolled readers
   linked some of those files by name. No tokenizer exception can escape the guard (round 7). A round-7 attempt to blank the rejected line and retry was removed in
   round 8: it read an unterminated string's body as code and lost a dump on the blanked line.

   The call's matching `)` is found with `close_paren_map`, one pass per file, so a file full of
   unclosed calls stays linear.

**`credential-exfil-via-webhook` (CRITICAL).** A Telegram Bot API send call
(`api.telegram.org/bot` + `sendDocument`/`sendMessage`/`sendPhoto`/`sendMediaGroup`) or a
Discord webhook URL (`discord(app)?.com/api/webhooks/`), in the SAME FILE as either a
serializing environment dump (not a bare copy) OR a reference to a well-known non-browser
credential-store path: `.aws/credentials`, an SSH private key (`.ssh` and
`id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519` on one line, so `os.path.join(home, ".ssh", "id_rsa")`
and `Path.home() / ".ssh" / "id_ed25519"` count, while the `.pub` public key does not),
`.git-credentials`, `.docker/config.json`, `.kube/config`. `.npmrc` and `.pypirc` are left out
for the reason `credential-file-path-reference` leaves `.npmrc` out: they are ordinary package
configuration that release bots read for unrelated reasons. A notification helper reading only
its own bot token from the environment, with no full dump and no credential file reference,
does not match — the source's own disclosed false-positive boundary.

**Deliberately narrower than the source:**

- Approximates the source's full dataflow taint rule with a statement-level, flow-insensitive
  name link (above) rather than building a dataflow engine. It started as same-file
  co-occurrence, which fired CRITICAL on a dump logged locally next to an unrelated telemetry
  post (PR #1093 review, round 1).
- The source's third YARA rule (environment dump + host-identity collection + generic HTTP
  send, no bot/webhook requirement) is dropped: its core signal — an environment dump next to
  a network send — is already the broader `environ-dump-network-sink` rule above.
- Raw `socket.send`/`sendall`/`sendto` sinks are dropped from both rules, to avoid chasing
  every unrelated `.send(...)` call in a file that also happens to dump environment variables
  for a completely different reason.
- `environ-dump-network-sink`'s network-send half only recognizes Python call shapes; a JS
  environment dump sent via `fetch()`/`axios`/`XMLHttpRequest` is not yet wired in (the
  Telegram/Discord webhook rule has no such gap, since its channel marker is language-agnostic
  text).

**Inline opt-out pragma:** `# security: allow-environ-dump-to-network`.

## When NOT to flag

- **Reading one named environment variable** — ordinary configuration.
- **Dumping the environment with no network send that carries it** (a local debug print,
  even in a file that also makes an unrelated `requests.post`).
- **Copying the environment for a child process** (`subprocess.run(cmd, env=dict(os.environ))`),
  even in a file that posts a notification to Discord or Telegram.
- **A Telegram/Discord notification helper reading only its own bot token**, with no full
  environment dump and no credential-store file reference, including one that reads `.npmrc`,
  `.pypirc` or an SSH public key.

Use the pragma `# security: allow-environ-dump-to-network` for a genuinely consented,
user-initiated diagnostics/support-bundle flow.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_json_dumps_environ_sent_via_requests_post` | `json.dumps(dict(os.environ))` assigned, then sent by name via `requests.post` — fires CRITICAL |
| `test_fires_on_str_environ_sent_via_urllib` | `str(os.environ)` + `urllib.request` with `data=data` (keyword value, not name) — fires |
| `test_fires_on_dict_environ_passed_inline_as_json_kwarg` | `requests.post(url, json=dict(os.environ))` — inline copy fires |
| `test_fires_on_environ_copies_passed_inline` | `json=os.environ.copy()` and `json=dict(os.environ.items())` inline — fire |
| `test_fires_on_dump_inside_dict_payload_sent_later` | a dump inside a multi-line dict literal, the dict sent later — fires, anchored at the dump |
| `test_fires_on_dump_reassigned_before_send` | one assignment hop (`body = d.encode()`) before the send — fires |
| `test_fires_when_a_later_dump_is_sent_after_a_local_one` | a benign local dump first, a sent dump second — fires on the second |
| `test_env_dump_kept_local_does_not_fire_on_unrelated_requests_post` | FP-bait: a dump printed locally plus an unrelated telemetry post — silent |
| `test_keyword_name_matching_a_dump_variable_does_not_link` | FP-bait: a local dump in `data` plus an unrelated post with a `data=` keyword — silent |
| `test_environ_copy_for_a_subprocess_does_not_fire` | FP-bait: `env=dict(os.environ)` for a subprocess, next to a Discord notifier or an unrelated post — silent |
| `test_fires_after_a_multiline_triple_quoted_call_argument` | an `ArgumentParser(description="""...""")` before the dump, and a dump inside an f-triple-quoted payload — fire |
| `test_prefixed_literal_followed_by_another_quote_still_links` | `f"{BASE_URL}"`, `f"id={os.getpid()}"`, `f""`, `b"/"` and a hop, each followed by another quote on the line: fire (round 4) |
| `test_plain_literals_after_a_prefixed_one_are_still_blanked` | FP-bait: a dict key and a bytes word after an f-string on the same line: silent |
| `test_multiline_triple_quoted_templates_link` | a dump in an f-triple-quoted template, the hop form, `"""..""" + p`, and `""".format(payload)` / `""" % payload` closing lines: fire |
| `test_triple_quoted_literal_words_do_not_link` | FP-bait: a tainted name's word inside a plain triple-quoted argument: silent |
| `test_dump_link_is_linear_on_a_line_of_escaped_quotes` | linear on a line-continued string of escaped quotes (the shared `strip_python_line_comment` is not: #1009) |
| `test_pep701_same_quote_f_strings_link` | same-quote keys, `",".join`, a ternary of literals, a nested f-string, an f-triple and `rf"..."` around the tainted name: fire |
| `test_literal_text_inside_an_f_string_does_not_link` | FP-bait: `f"{cfg["payload"]}"`, `f"{row['payload']}"` and `f"{{payload}}"`: silent |
| `test_a_hash_in_a_triple_quoted_f_string_spec_does_not_hide_the_link` | a `{color:#x}` / `{n:#06x}` / indented `{color:#o}` spec in a triple-quoted f-string before the dump: fire (round 6) |
| `test_format_spec_text_does_not_link` | FP-bait: `f"{n:=d}"` and `\N{DASH}` in a spec, each naming a tainted variable: silent |
| `test_code_view_keeps_only_code_tokens` | the tokenizer view blanks a docstring, f-string text, a spec, `{{ }}` and a comment, keeps expression names, and its statements are logical lines |
| `test_a_file_that_does_not_tokenize_keeps_only_the_inline_check` | an unclosed bracket at EOF: the inline dump fires, the by-name link does not; a Python 2 `print "x"` still tokenizes and keeps the link |
| `test_a_nul_byte_file_does_not_take_the_guard_down` / `test_any_tokenizer_exception_degrades_instead_of_raising` | a NUL decoy file (tokenize raised SystemError) no longer drops the real exfil file's finding; any tokenizer exception degrades (round 7) |
| `test_a_tab_mixed_python2_file_keeps_the_link` / `test_many_tab_mixed_lines_keep_the_link` | Python 2 tab/space mixes (one, and fifteen): fire |
| `test_a_file_the_tokenizer_rejects_keeps_exactly_the_inline_check` | a latin-1 string mangled by `read()` and a t-string under Python < 3.14: by-name is not followed; a dump inline on the rejected line of a multi-line call still fires (round 8) |
| `test_an_unterminated_docstring_example_is_not_code` | FP-bait: a dump-and-send example inside an unterminated docstring: silent (round 8) |
| `test_a_dump_comprehension_with_a_short_comment_still_links` / `test_an_allow_listed_env_subset_is_not_a_dump` | a short comment inside the comprehension still fits the 80-character window; FP-bait: an 11-name allow-listed subset is not the whole environment |
| `test_each_view_gate_clause_opens_the_check` | `f"{d["#"]}"` before `str(os.environ)` and before `os.environ.copy()`: each gate clause on the tokenizer view fires on its own |
| `test_a_dump_only_the_view_shows_still_feeds_the_webhook_rule` | a dump behind `f"{d["#"]}"` is also the Discord-webhook rule's exfil signal: fires at the webhook line |
| `test_a_hash_inside_an_f_string_key_does_not_hide_the_dump` | `f"{d["#"]}"` before an inline or assigned dump: fires (the gate reads the tokenizer view) |
| `test_the_first_carrying_call_sets_the_reported_line` | calls in order, inline then by name: the reported line does not move |
| `test_blank_and_comment_lines_do_not_break_a_hop` / `test_a_dump_spelled_inside_a_string_argument_is_not_inline` | a blank or comment line does not end a statement; a dump spelled inside a string argument is not inline (FP-bait) |
| `test_string_literal_words_and_attribute_names_do_not_link` | FP-bait: a dict-key string, a URL word, and `resp.data`, each sharing a tainted name — silent |
| `test_interpolated_and_concatenated_references_still_link` | `f"{p}"` and `"env=" + d` still link — fire |
| `test_fires_on_annotated_assignment_of_the_dump` | `payload: str = json.dumps(dict(os.environ))` then sent — fires |
| `test_compound_statement_keyword_is_not_an_assignment_target` | FP-bait: `else: snapshot = ...` does not taint a name `else` — silent |
| `test_js_env_dump_alone_does_not_fire_known_limitation` | disclosed limitation: JS `fetch()` network-send half not wired in — silent |
| `test_env_dump_without_network_send_does_not_fire` | FP-bait: a local-only env dump — silent |
| `test_single_variable_read_does_not_fire` | FP-bait: `os.environ["API_KEY"]` — silent |
| `test_fires_on_telegram_bot_with_environ_dump` | Telegram bot send + env dump — fires |
| `test_fires_on_discord_webhook_with_credential_store_path` | Discord webhook + `.aws/credentials` reference — fires |
| `test_telegram_bot_token_read_alone_does_not_fire` | FP-bait: a notification helper reading only its own bot token — silent |
| `test_discord_notifier_mentioning_npmrc_does_not_fire` | FP-bait: a Python and a JS notifier that read or write `.npmrc` in code — silent |
| `test_telegram_notifier_mentioning_pypirc_does_not_fire` | FP-bait: a Telegram notifier that reads `~/.pypirc` — silent |
| `test_telegram_notifier_mentioning_bare_id_rsa_does_not_fire` | FP-bait: an `id_rsa` label with no `.ssh` — silent |
| `test_telegram_notifier_with_ssh_id_rsa_path_still_fires` | `~/.ssh/id_rsa` + Telegram send — still fires |
| `test_webhook_with_built_ssh_private_key_path_fires` | `os.path.join(home, ".ssh", "id_rsa")` and `Path.home() / ".ssh" / "id_ed25519"` — fire |
| `test_webhook_with_ssh_public_key_does_not_fire` | FP-bait: `~/.ssh/id_rsa.pub` next to a webhook — silent |
| `test_discord_notification_helper_alone_does_not_fire` | FP-bait: an ordinary build-status webhook post — silent |
| `test_docstring_prose_alone_does_not_fire` | FP-bait: every trigger phrase mentioned only in a docstring — silent |
| `test_pragma_silences_all_rules` | the inline pragma silences every rule |
| `test_scan_is_linear_on_unclosed_network_calls` | (slow) 2000 unclosed `requests.post(` lines scan in linear time, and a real send appended still fires |
| `test_applies_requires_python_js_or_ts` | `applies()` gate |
| `test_js_dump_spelled_in_a_string_does_not_feed_the_webhook_rule` | #1055 FP direction: `JSON.stringify(process.env)` spelled in a warning string or template text next to a real Discord webhook — silent |
| `test_js_real_dump_still_feeds_the_webhook_rule` | #1055: the real dump fires, including one nested in `${...}` and one after a quoted copy; a credential-store path literal still counts |
| `test_js_pragma_still_suppresses_a_code_anchored_dump` | the pragma still silences a finding the anchor rule kept |

## Known bypasses

- **Not full dataflow.** The name link is flow-insensitive and statement-level. It reads one
  assignment shape, `name = ...` or `a, b = ...` (optionally annotated on one line) at the start
  of a logical line, so it does not follow: attribute or subscript targets (`self.p = ...`,
  `d["env"] = ...`); augmented assignment (`+=`); chained (`a = b = dump`), parenthesised
  (`(a, b) = ...`), trailing-comma, walrus (`(p := dump)`), `for`-target or default-argument
  bindings; a statement joined by `;` or sitting after `if c:` on the same line; an annotation
  that spans lines; a value returned through a helper function; or more than three assignment
  hops. A dump/send split across two files is never connected. A name written only inside a
  plain string (`"{payload}".format(**locals())`) is not read, because string words are blank
  to keep dict keys and URL words from linking. A file the tokenizer rejects (an unterminated
  string, including a latin-1 one whose byte `read()` dropped; a literal newer than the running
  Python, such as a t-string before 3.14; a NUL) gets only the inline check. A comment long enough to exhaust the
  comprehension dump's 80-character window hides that dump (inline or assigned). The window is
  also the only thing that tells an allow-listed subset from the whole environment: a short
  allow-list (`{k: v for k, v in os.environ.items() if k in ("PATH",)}`) reads as a dump. A
  backslash-continued assignment target is not read. These edges are tracked together in #1118.
- **A bare copy held in a variable.** `p = dict(os.environ)` (or `os.environ.copy()`) followed by
  `requests.post(url, json=p)` is silent: a bare copy counts only as the send call's own
  argument, because the same copy-then-pass shape is how a subprocess `env=` is built. Tracked in
  #1109.
- **Very large argument lists.** Only the first 8 KB of a send call's argument list is read, so a
  dump or tainted name placed after more than 8 KB of other payload is missed (a cap that keeps a
  hostile file of nested calls bounded; #1112).
- **Network-send vocabulary.** `requests.Session().post`, `aiohttp`, and `from os import
  environ; dict(environ)` are not recognized.
- **JS/TS anchoring (#1055).** The JS dump (`JSON.stringify(process.env)`) counts only when the
  `(` of `JSON.stringify(` is live code on the anchor mask (`js_code_matches` over
  `strip_js_comments(text, strip_strings=True, keep_substitutions=True)`), so a dump spelled out in
  a warning string no longer feeds the webhook rule; a dump inside `${...}` still does. The webhook
  URL, the Telegram send method and the credential-store path are literals by nature and stay
  plain matches. Residual: the anchor mask inherits the #543 sub-lexer residual: a `{` inside a regex or comment in one `${...}` substitution, then a `}` in a later one, rebalances the frame, so the code between the two reads as template text and an anchor there is not code (the accepted trade pinned by `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`); a dump there is missed, which errs toward silence.
- **JS network-send gap (disclosed above).**
- **Fixed credential-store path vocabulary.** A credential file not in the fixed list is not
  recognized, and an SSH key path built across two statements (`ssh = "~/.ssh"`, then
  `ssh + "/id_rsa"`) is missed by the one-line anchor.

## What this guard does NOT prove

- That a flagged link is actually an exfiltration chain — the name link is flow-insensitive, so
  a name reused for unrelated data later in the file can still link.
- That code WITHOUT a matching pattern never exfiltrates the environment — a dump assembled
  piecemeal, passed through a helper function or across files, or sent via an unrecognized
  network API is not caught.

# Citations

[1] agentsec checklist item `8-environ-dump-to-network` (§8)
[2] OWASP:A08, CWE-200
[3] MITRE ATT&CK T1552.001 (Credentials in Files), T1041 (Exfiltration Over C2 Channel)
[4] rakshit-737/warden-supply-chain-security `warden-python.yml` (`environ-dump-to-network`), `warden_exfiltration.yar`
