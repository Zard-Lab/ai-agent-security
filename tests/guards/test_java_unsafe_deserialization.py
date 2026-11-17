from __future__ import annotations

from agentsec.guards.java_unsafe_deserialization import JavaUnsafeDeserializationGuard
from tests.guards._common import *  # noqa: F401,F403


def test_java_unsafe_deserialization_flags_object_input_stream_readobject(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "class T { Object m(java.io.ObjectInputStream ois) throws Exception "
        "{ return ois.readObject(); } }\n",
        encoding="utf-8",
    )
    findings = JavaUnsafeDeserializationGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-unsafe-deserialization/object-input-stream"
    assert findings[0].severity == "critical"


def test_java_unsafe_deserialization_flags_readunshared(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "class T { Object m(java.io.ObjectInputStream ois) throws Exception "
        "{ return ois.readUnshared(); } }\n",
        encoding="utf-8",
    )
    findings = JavaUnsafeDeserializationGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-unsafe-deserialization/object-input-stream"


def test_java_unsafe_deserialization_flags_bare_readobject_graudit_subset(tmp_path: Path) -> None:
    # graudit's simpler ObjectInputStream/readObject(/resolveClass( signature is a verified
    # subset folded into this guard — the bare `.readObject()` match must not be narrower than
    # that, so it must fire even without an ObjectInputStream-typed receiver in view.
    (tmp_path / "T.java").write_text(
        "class T { Object m(SomeStream s) throws Exception { return s.readObject(); } }\n",
        encoding="utf-8",
    )
    findings = JavaUnsafeDeserializationGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-unsafe-deserialization/object-input-stream"


def test_java_unsafe_deserialization_flags_jackson_class(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)\nclass T {}\n",
        encoding="utf-8",
    )
    findings = JavaUnsafeDeserializationGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-unsafe-deserialization/jackson-polymorphic-typing"
    assert findings[0].severity == "critical"


def test_java_unsafe_deserialization_flags_jackson_minimal_class(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "@JsonTypeInfo(use = JsonTypeInfo.Id.MINIMAL_CLASS)\nclass T {}\n",
        encoding="utf-8",
    )
    findings = JavaUnsafeDeserializationGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-unsafe-deserialization/jackson-polymorphic-typing"


def test_java_unsafe_deserialization_silent_on_jackson_safe_name_mode(tmp_path: Path) -> None:
    # FP-bait: Jackson's safe Id.NAME mode (developer-controlled logical name -> class mapping,
    # not an attacker-supplied class name) must not fire.
    (tmp_path / "T.java").write_text(
        "@JsonTypeInfo(use = JsonTypeInfo.Id.NAME)\nclass T {}\n",
        encoding="utf-8",
    )
    assert JavaUnsafeDeserializationGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_unsafe_deserialization_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "class T { Object m(java.io.ObjectInputStream ois) throws Exception {\n"
        "  return ois.readObject(); // security: allow-unsafe-deserialize\n"
        "} }\n",
        encoding="utf-8",
    )
    assert JavaUnsafeDeserializationGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_unsafe_deserialization_silent_in_line_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `//` comment must not fire.
    (tmp_path / "T.java").write_text(
        "class T { void m() {\n"
        "  // ois.readObject() is dangerous, don't call it on untrusted input\n"
        "  int real = 1;\n"
        "} }\n",
        encoding="utf-8",
    )
    assert JavaUnsafeDeserializationGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_unsafe_deserialization_ignores_javadoc_block_comment(tmp_path: Path) -> None:
    # FP-bait for the /** */ handling in strip_java_comments: an example inside a real Javadoc
    # block comment must not fire.
    (tmp_path / "T.java").write_text(
        "/**\n * ois.readObject() is an example, do not call this on untrusted input\n */\n"
        "class T { void m() { int real = 1; } }\n",
        encoding="utf-8",
    )
    assert JavaUnsafeDeserializationGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_unsafe_deserialization_not_applicable_without_java() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert JavaUnsafeDeserializationGuard().applies(prof) is False


def test_java_unsafe_deserialization_skips_maven_test_tree(tmp_path: Path) -> None:
    # Narrowing gate (PR #839 review): Maven/Gradle put test sources under `src/test/java`, whose
    # `test` segment `is_nonproduct_path` reads as non-product. Both trees carry the SAME violation
    # in one run, so this pins the skip AND the direction traded against it — production code under
    # `src/main/java` must still fire.
    src = (
        "class T { Object m(java.io.ObjectInputStream ois) throws Exception "
        "{ return ois.readObject(); } }\n"
    )
    for tree in ("main", "test"):
        d = tmp_path / "src" / tree / "java"
        d.mkdir(parents=True)
        (d / "T.java").write_text(src, encoding="utf-8")
    findings = JavaUnsafeDeserializationGuard().run(tmp_path, _javaprof(tmp_path))
    assert findings
    assert {f.location.split(":")[0].replace("\\", "/") for f in findings} == {"src/main/java/T.java"}
