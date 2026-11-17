from __future__ import annotations

from agentsec.guards.credential_file_path_reference import CredentialFilePathReferenceGuard
from tests.guards._common import *  # noqa: F401,F403


def test_credential_file_path_flags_ssh_key(tmp_path: Path) -> None:
    (tmp_path / "steal.py").write_text(
        'with open(os.path.expanduser("~/.ssh/id_rsa")) as f:\n'
        "    key_data = f.read()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = CredentialFilePathReferenceGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "credential-file-path-reference/known-credential-path"
    assert findings[0].severity == "high"

def test_credential_file_path_silent_public_key_read(tmp_path: Path) -> None:
    # FP-bait (fixed 2026-08-04): reading a PUBLIC key is routine and harmless -- `\b` alone
    # would match inside "id_rsa.pub" (the "." counts as a word boundary), so the pattern
    # needs an explicit (?!\.pub\b) exclusion.
    (tmp_path / "read_pub.py").write_text(
        'with open(os.path.expanduser("~/.ssh/id_rsa.pub")) as f:\n'
        "    pub_key = f.read()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert CredentialFilePathReferenceGuard().run(tmp_path, profile) == []

def test_credential_file_path_flags_aws_credentials(tmp_path: Path) -> None:
    (tmp_path / "steal.py").write_text(
        'aws_creds = open("~/.aws/credentials").read()\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = CredentialFilePathReferenceGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_credential_file_path_flags_etc_shadow(tmp_path: Path) -> None:
    (tmp_path / "steal.sh").write_text(
        "cat /etc/shadow > /tmp/out.txt\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = CredentialFilePathReferenceGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_credential_file_path_flags_kube_config(tmp_path: Path) -> None:
    (tmp_path / "steal.js").write_text(
        'const kubeconfig = fs.readFileSync("~/.kube/config");\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = CredentialFilePathReferenceGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_credential_file_path_silent_unrelated_file(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        'config_path = "~/.myapp/config.json"\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert CredentialFilePathReferenceGuard().run(tmp_path, profile) == []

def test_credential_file_path_silent_comment(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "# Note: this app does NOT read ~/.ssh/id_rsa\n"
        "x = 1\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert CredentialFilePathReferenceGuard().run(tmp_path, profile) == []

def test_credential_file_path_pragma_silences(tmp_path: Path) -> None:
    content = (
        '# security: allow-credential-file-path\n'
        'open("~/.ssh/id_rsa")\n'
    )
    (tmp_path / "rotate.py").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert CredentialFilePathReferenceGuard().run(tmp_path, profile) == []

def test_credential_file_path_silent_kubeconfig_flag(tmp_path: Path) -> None:
    # Regression (PR #393 review addendum): a bare `--kubeconfig` CLI flag or a
    # `get_kubeconfig` identifier is NOT a credential-file path -- the `kubeconfig` match is
    # path-anchored, so neither false-fires.
    (tmp_path / "cli.py").write_text(
        'parser.add_argument("--kubeconfig", help="path to kube config")\n'
        "def get_kubeconfig():\n"
        "    return load_config()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert CredentialFilePathReferenceGuard().run(tmp_path, profile) == []

def test_credential_file_path_flags_path_anchored_kubeconfig(tmp_path: Path) -> None:
    # ...but a real `.../kubeconfig` file path (separator in front) still fires.
    (tmp_path / "steal.sh").write_text(
        "cp /home/user/kubeconfig /tmp/exfil\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert len(CredentialFilePathReferenceGuard().run(tmp_path, profile)) == 1

def test_credential_file_path_covers_shell_only_repo(tmp_path: Path) -> None:
    # Regression (PR #393 review #1): universal guard fires on a shell-only repo (no python).
    (tmp_path / "steal.sh").write_text("cat /etc/shadow > /tmp/out\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features=set())
    assert CredentialFilePathReferenceGuard().applies(profile) is True
    assert len(CredentialFilePathReferenceGuard().run(tmp_path, profile)) == 1

def test_credential_file_path_skips_nonproduct_path(tmp_path: Path) -> None:
    # Regression (PR #393 review #2): a fixture string `~/.ssh/id_rsa` in a test file is skipped.
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_keys.py").write_text('KEY = "~/.ssh/id_rsa"\n', encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert CredentialFilePathReferenceGuard().run(tmp_path, profile) == []

def test_credential_file_path_applies_universally() -> None:
    # Universal guard: credential-path references can appear in any stack.
    assert CredentialFilePathReferenceGuard().applies(mkprofile(Path("/tmp"), features={"java"})) is True
    assert CredentialFilePathReferenceGuard().applies(mkprofile(Path("/tmp"), features=set())) is True

# ── Symlink-to-credential-directory extension (batch, CVE-2026-39861) ──────────────

def test_credential_file_path_flags_symlink_to_bare_ssh_dir(tmp_path: Path) -> None:
    (tmp_path / "setup.sh").write_text(
        "#!/bin/bash\nln -s ~/.ssh /tmp/workspace-escape\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = CredentialFilePathReferenceGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "credential-file-path-reference/symlink-to-credential-target"

def test_credential_file_path_flags_symlink_to_etc_passwd(tmp_path: Path) -> None:
    (tmp_path / "setup.sh").write_text(
        "ln -sf /etc/passwd ./workspace/link\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = CredentialFilePathReferenceGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "credential-file-path-reference/symlink-to-credential-target"

def test_credential_file_path_silent_symlink_to_ordinary_project_file(tmp_path: Path) -> None:
    # FP-bait: a symlink to an ordinary project file/directory carries no sensitive target.
    (tmp_path / "setup.sh").write_text(
        "ln -s ../shared/lib ./vendor/lib\nln -s node_modules/.bin/eslint ./bin/eslint\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert CredentialFilePathReferenceGuard().run(tmp_path, profile) == []

def test_credential_file_path_silent_mkdir_ssh_no_symlink(tmp_path: Path) -> None:
    # FP-bait: a bare directory mention with no `ln` verb is ordinary setup, not this signal.
    (tmp_path / "setup.sh").write_text(
        "mkdir -p ~/.ssh\nchmod 700 ~/.ssh\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert CredentialFilePathReferenceGuard().run(tmp_path, profile) == []

def test_credential_file_path_silent_symlink_to_public_key(tmp_path: Path) -> None:
    # FP-bait: symlinking a PUBLIC key is routine and harmless. Pins two things at once:
    # the bare-directory alternative's negative lookahead must not match when a specific
    # file follows, AND the specific-file alternative's own (?!\.pub\b) exclusion (fixed
    # alongside this extension) must not fire on the .pub filename either.
    (tmp_path / "setup.sh").write_text(
        "ln -s ~/.ssh/id_rsa.pub ./shared/id_rsa.pub\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert CredentialFilePathReferenceGuard().run(tmp_path, profile) == []
