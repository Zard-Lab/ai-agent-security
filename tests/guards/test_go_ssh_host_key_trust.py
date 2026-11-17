from __future__ import annotations

from agentsec.guards.go_ssh_host_key_trust import GoSshHostKeyTrustGuard
from tests.guards._common import *  # noqa: F401,F403


def test_go_ssh_host_key_trust_fires_on_struct_literal(tmp_path: Path) -> None:
    (tmp_path / "client.go").write_text(
        "package main\n"
        "\n"
        "import \"golang.org/x/crypto/ssh\"\n"
        "\n"
        "func connect() {\n"
        "\tconfig := &ssh.ClientConfig{\n"
        "\t\tUser:            \"deploy\",\n"
        "\t\tHostKeyCallback: ssh.InsecureIgnoreHostKey(),\n"
        "\t}\n"
        "\t_ = config\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    findings = GoSshHostKeyTrustGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "go-ssh-host-key-trust/insecure-ignore-host-key"
    assert findings[0].severity == "high"


def test_go_ssh_host_key_trust_fires_on_direct_call_argument(tmp_path: Path) -> None:
    # Passed directly as a call argument, not via a struct field — the guard fires on the
    # call itself regardless of the surrounding context it's used in.
    (tmp_path / "dial.go").write_text(
        "package main\n"
        "\n"
        "import \"golang.org/x/crypto/ssh\"\n"
        "\n"
        "func dial() {\n"
        "\tdialWithCallback(ssh.InsecureIgnoreHostKey())\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    findings = GoSshHostKeyTrustGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_go_ssh_host_key_trust_fires_on_indirect_assignment(tmp_path: Path) -> None:
    # Positive, indirect form: the call is assigned to an intermediate variable first, then
    # that variable is used as the HostKeyCallback value (`cb := ssh.InsecureIgnoreHostKey()`
    # ... `HostKeyCallback: cb`). Design decision (documented in the design doc's "Known
    # bypasses" section): this guard is a same-line text match on the call expression, not a
    # dataflow analysis, so it does NOT specifically recognize the `HostKeyCallback: cb`
    # usage site — but it still fires here, because the dangerous call text itself
    # (`ssh.InsecureIgnoreHostKey()`) is present verbatim on the assignment line, which is
    # sufficient: the call has to be written literally somewhere for the value to exist at
    # all within a single file/function. The finding is anchored to the CALL line, not the
    # later usage line.
    (tmp_path / "indirect.go").write_text(
        "package main\n"
        "\n"
        "import \"golang.org/x/crypto/ssh\"\n"
        "\n"
        "func connect() {\n"
        "\tcb := ssh.InsecureIgnoreHostKey()\n"
        "\tconfig := &ssh.ClientConfig{\n"
        "\t\tHostKeyCallback: cb,\n"
        "\t}\n"
        "\t_ = config\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    findings = GoSshHostKeyTrustGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].location.endswith(":6")


def test_go_ssh_host_key_trust_alias_only_indirection_not_detected(tmp_path: Path) -> None:
    # The stricter version of the above: the insecure call happens in one file/helper and
    # only the resulting HostKeyCallback value is threaded through this file — no literal
    # `ssh.InsecureIgnoreHostKey()` text appears here at all. This is the real bypass the
    # design doc documents: the guard is a same-line text match, not a dataflow analysis, so
    # it cannot follow a value across an assignment or a function boundary.
    (tmp_path / "helper.go").write_text(
        "package main\n"
        "\n"
        "import \"golang.org/x/crypto/ssh\"\n"
        "\n"
        "func buildConfig(cb ssh.HostKeyCallback) *ssh.ClientConfig {\n"
        "\treturn &ssh.ClientConfig{HostKeyCallback: cb}\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert GoSshHostKeyTrustGuard().run(tmp_path, profile) == []


def test_go_ssh_host_key_trust_silent_on_fixed_host_key(tmp_path: Path) -> None:
    # FP-bait: the safe idiom — a single known host key pinned via ssh.FixedHostKey — stays
    # silent.
    (tmp_path / "client.go").write_text(
        "package main\n"
        "\n"
        "import \"golang.org/x/crypto/ssh\"\n"
        "\n"
        "func connect(pub ssh.PublicKey) {\n"
        "\tconfig := &ssh.ClientConfig{\n"
        "\t\tHostKeyCallback: ssh.FixedHostKey(pub),\n"
        "\t}\n"
        "\t_ = config\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert GoSshHostKeyTrustGuard().run(tmp_path, profile) == []


def test_go_ssh_host_key_trust_silent_on_knownhosts_new(tmp_path: Path) -> None:
    # FP-bait: the safe idiom — a known_hosts file loaded via knownhosts.New — stays silent.
    (tmp_path / "client.go").write_text(
        "package main\n"
        "\n"
        "import (\n"
        "\t\"golang.org/x/crypto/ssh\"\n"
        "\t\"golang.org/x/crypto/ssh/knownhosts\"\n"
        ")\n"
        "\n"
        "func connect() error {\n"
        "\thostKeyCallback, err := knownhosts.New(\"/home/deploy/.ssh/known_hosts\")\n"
        "\tif err != nil {\n"
        "\t\treturn err\n"
        "\t}\n"
        "\tconfig := &ssh.ClientConfig{\n"
        "\t\tHostKeyCallback: hostKeyCallback,\n"
        "\t}\n"
        "\t_ = config\n"
        "\treturn nil\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert GoSshHostKeyTrustGuard().run(tmp_path, profile) == []


def test_go_ssh_host_key_trust_silent_on_commented_out_reference(tmp_path: Path) -> None:
    # FP-bait: the function name appearing only inside a `//` comment must not fire —
    # comment-stripping keeps this silent.
    (tmp_path / "client.go").write_text(
        "package main\n"
        "\n"
        "import \"golang.org/x/crypto/ssh\"\n"
        "\n"
        "func connect() {\n"
        "\t// Do NOT use ssh.InsecureIgnoreHostKey() here, it disables verification.\n"
        "\tconfig := &ssh.ClientConfig{\n"
        "\t\tHostKeyCallback: ssh.FixedHostKey(nil),\n"
        "\t}\n"
        "\t_ = config\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert GoSshHostKeyTrustGuard().run(tmp_path, profile) == []


def test_go_ssh_host_key_trust_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "client.go").write_text(
        "package main\n"
        "\n"
        "import \"golang.org/x/crypto/ssh\"\n"
        "\n"
        "func connect() {\n"
        "\tconfig := &ssh.ClientConfig{\n"
        "\t\tHostKeyCallback: ssh.InsecureIgnoreHostKey(), // security: allow-go-ssh-host-key-trust\n"
        "\t}\n"
        "\t_ = config\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert GoSshHostKeyTrustGuard().run(tmp_path, profile) == []


def test_go_ssh_host_key_trust_comment_strip_both_directions(tmp_path: Path) -> None:
    # Both-directions comment-stripping check: a stray, unrelated `//` comment on an EARLIER
    # line must not desync the scanner and eat a REAL call that appears later in the same
    # file — comment-stripping is line-scoped for `//`, but this pins the whole-file behavior.
    (tmp_path / "client.go").write_text(
        "package main\n"
        "\n"
        "import \"golang.org/x/crypto/ssh\"\n"
        "\n"
        "// connect dials the remote host. TODO: tighten timeouts.\n"
        "func connect() {\n"
        "\tconfig := &ssh.ClientConfig{\n"
        "\t\tHostKeyCallback: ssh.InsecureIgnoreHostKey(),\n"
        "\t}\n"
        "\t_ = config\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    findings = GoSshHostKeyTrustGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].location.endswith(":8")


def test_go_ssh_host_key_trust_not_applies_without_go(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python"})
    assert GoSshHostKeyTrustGuard().applies(profile) is False


def test_go_ssh_host_key_trust_nonproduct_path_skipped(tmp_path: Path) -> None:
    # Independent review finding: run() never called is_nonproduct_path, so a project's own
    # test fixture demonstrating the insecure pattern would false-fire on every scan.
    tests_dir = tmp_path / "tests" / "fixtures"
    tests_dir.mkdir(parents=True)
    (tests_dir / "vulnerable_example.go").write_text(
        "package fixtures\n\nvar cb = ssh.InsecureIgnoreHostKey()\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert GoSshHostKeyTrustGuard().run(tmp_path, profile) == []
