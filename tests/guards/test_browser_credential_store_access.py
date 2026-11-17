from __future__ import annotations

from agentsec.guards.browser_credential_store_access import BrowserCredentialStoreAccessGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"python"}, python_dirs=["."])


# --- chromium-master-key ---------------------------------------------------------------------


def test_fires_on_chromium_master_key_decryption(tmp_path: Path) -> None:
    (tmp_path / "steal.py").write_text(
        "import json, win32crypt\n"
        "data = json.load(open('Local State'))\n"
        "key = data['os_crypt']['encrypted_key']\n"
        "decrypted = win32crypt.CryptUnprotectData(key)\n",
        encoding="utf-8",
    )
    findings = BrowserCredentialStoreAccessGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "browser-credential-store-access/chromium-master-key" for f in findings)
    assert all(f.severity == "critical" for f in findings)


def test_local_state_alone_does_not_fire(tmp_path: Path) -> None:
    # FP bait: a single artefact (no encrypted_key, no DPAPI) is not credential theft.
    (tmp_path / "config.py").write_text(
        "APP_STATE_FILE = 'Local State'\n",
        encoding="utf-8",
    )
    assert BrowserCredentialStoreAccessGuard().run(tmp_path, _prof(tmp_path)) == []


# --- chromium-login-data ----------------------------------------------------------------------


def test_fires_on_chromium_login_data_password_theft(tmp_path: Path) -> None:
    (tmp_path / "steal.py").write_text(
        "import sqlite3\n"
        "conn = sqlite3.connect('Login Data')\n"
        "rows = conn.execute('SELECT password_value FROM logins').fetchall()\n",
        encoding="utf-8",
    )
    findings = BrowserCredentialStoreAccessGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "browser-credential-store-access/chromium-login-data" for f in findings)


def test_login_data_without_password_value_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "notes.py").write_text(
        "BACKUP_SOURCE = 'Login Data'\n"
        "conn = sqlite3.connect(BACKUP_SOURCE)\n",
        encoding="utf-8",
    )
    assert BrowserCredentialStoreAccessGuard().run(tmp_path, _prof(tmp_path)) == []


# --- firefox-credential-store ------------------------------------------------------------------


def test_fires_on_firefox_credential_store_pair(tmp_path: Path) -> None:
    (tmp_path / "steal.py").write_text(
        "profile_files = ['key4.db', 'logins.json']\n",
        encoding="utf-8",
    )
    findings = BrowserCredentialStoreAccessGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "browser-credential-store-access/firefox-credential-store" for f in findings)


def test_key4_db_alone_does_not_fire(tmp_path: Path) -> None:
    # FP bait: a profile-backup tool copying whole directories often names only one file.
    (tmp_path / "backup.py").write_text(
        "nss_db = 'key4.db'\n",
        encoding="utf-8",
    )
    assert BrowserCredentialStoreAccessGuard().run(tmp_path, _prof(tmp_path)) == []


# --- discord-token-grabber-webhook --------------------------------------------------------------


def test_fires_on_discord_webhook_with_encrypted_token_prefix(tmp_path: Path) -> None:
    (tmp_path / "grab.py").write_text(
        "WEBHOOK = 'https://discord.com/api/webhooks/123/abc'\n"
        "token_marker = 'dQw4w9WgXcQ:' + encrypted\n",
        encoding="utf-8",
    )
    findings = BrowserCredentialStoreAccessGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "browser-credential-store-access/discord-token-grabber-webhook" for f in findings)


def test_fires_on_discord_webhook_with_leveldb_client_path(tmp_path: Path) -> None:
    (tmp_path / "grab.py").write_text(
        "WEBHOOK = 'https://discordapp.com/api/webhooks/123/abc'\n"
        "path = r'%AppData%\\discord\\Local Storage\\leveldb'\n",
        encoding="utf-8",
    )
    findings = BrowserCredentialStoreAccessGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "browser-credential-store-access/discord-token-grabber-webhook" for f in findings)


def test_discord_webhook_alone_does_not_fire(tmp_path: Path) -> None:
    # FP bait: an ordinary Discord notification bot posts to a webhook with no token-grabber
    # signal at all -- this is the source's own disclosed false-positive boundary.
    (tmp_path / "notify.py").write_text(
        "WEBHOOK = 'https://discord.com/api/webhooks/123/abc'\n"
        "requests.post(WEBHOOK, json={'content': 'build finished'})\n",
        encoding="utf-8",
    )
    assert BrowserCredentialStoreAccessGuard().run(tmp_path, _prof(tmp_path)) == []


# --- docstring self-reference / pragma / applies -------------------------------------------
# Note: this guard's own `canary_plant` literal (and its detection regexes' own pattern text,
# e.g. `re.compile(r"Local State")`) necessarily contain the real trigger strings -- that is
# how a canary proves the guard fires, and a regex cannot match "Local State" without the
# characters "Local State" appearing in its own pattern literal. Those are expected self-
# reference findings, handled by the standard Loop C self-audit baseline (`agentsec-
# exceptions.json`), the same way every other guard's own canary/pattern text is baselined --
# not something a guard can or should design around. Only the module DOCSTRING (prose, no
# code) is tested here, via `strip_python_strings` blanking triple-quoted content.


def test_docstring_prose_alone_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "notes.py").write_text(
        '"""Discusses Local State, encrypted_key, CryptUnprotectData, Login Data, '
        "password_value, sqlite, key4.db, logins.json, a discord.com/api/webhooks/ URL, "
        'dQw4w9WgXcQ:, Local Storage, leveldb, and a discord client path, all in prose."""\n'
        "def run():\n"
        "    return None\n",
        encoding="utf-8",
    )
    assert BrowserCredentialStoreAccessGuard().run(tmp_path, _prof(tmp_path)) == []


def test_pragma_silences_all_rules(tmp_path: Path) -> None:
    (tmp_path / "steal.py").write_text(
        "# security: allow-browser-credential-store-access\n"
        "data = json.load(open('Local State'))\n"
        "key = data['os_crypt']['encrypted_key']\n"
        "decrypted = win32crypt.CryptUnprotectData(key)\n",
        encoding="utf-8",
    )
    assert BrowserCredentialStoreAccessGuard().run(tmp_path, _prof(tmp_path)) == []


def test_applies_requires_python_js_or_ts(tmp_path: Path) -> None:
    guard = BrowserCredentialStoreAccessGuard()
    assert guard.applies(mkprofile(tmp_path, features={"python"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"javascript"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"typescript"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"docker"})) is False
