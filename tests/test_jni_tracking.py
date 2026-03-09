from __future__ import annotations

import argparse
from pathlib import Path


def _import_surface():
    try:
        from src.core.jni.jni_surface import JniSurfaceAnalyzer  # type: ignore

        return JniSurfaceAnalyzer
    except Exception:
        from core.jni.jni_surface import JniSurfaceAnalyzer  # type: ignore

        return JniSurfaceAnalyzer


def _import_resolver():
    try:
        from src.core.jni.native_resolver import NativeBindingResolver  # type: ignore

        return NativeBindingResolver
    except Exception:
        from core.jni.native_resolver import NativeBindingResolver  # type: ignore

        return NativeBindingResolver


def _import_register_parser():
    try:
        from src.core.jni.jni_register_natives import RegisterNativesParser  # type: ignore

        return RegisterNativesParser
    except Exception:
        from core.jni.jni_register_natives import RegisterNativesParser  # type: ignore

        return RegisterNativesParser


def _import_invocation_analyzer():
    try:
        from src.core.jni.jni_invocation import JniInvocationAnalyzer  # type: ignore

        return JniInvocationAnalyzer
    except Exception:
        from core.jni.jni_invocation import JniInvocationAnalyzer  # type: ignore

        return JniInvocationAnalyzer


def _import_crosslang_components():
    try:
        from src.core.jni.native_ir import NativeIRBuilder  # type: ignore
        from src.core.jni.cross_language_points_to import CrossLanguagePointsToAnalyzer  # type: ignore
        from src.core.jni.native_taint_summaries import NativeTaintSummaryBuilder  # type: ignore

        return NativeIRBuilder, CrossLanguagePointsToAnalyzer, NativeTaintSummaryBuilder
    except Exception:
        from core.jni.native_ir import NativeIRBuilder  # type: ignore
        from core.jni.cross_language_points_to import CrossLanguagePointsToAnalyzer  # type: ignore
        from core.jni.native_taint_summaries import NativeTaintSummaryBuilder  # type: ignore

        return NativeIRBuilder, CrossLanguagePointsToAnalyzer, NativeTaintSummaryBuilder


def _import_crosslang_fact_adapters():
    try:
        from src.core.jni.taie_facts_ingestor import TaiEFactsIngestor  # type: ignore
        from src.core.jni.svf_output_adapter import SvfOutputAdapter  # type: ignore

        return TaiEFactsIngestor, SvfOutputAdapter
    except Exception:
        from core.jni.taie_facts_ingestor import TaiEFactsIngestor  # type: ignore
        from core.jni.svf_output_adapter import SvfOutputAdapter  # type: ignore

        return TaiEFactsIngestor, SvfOutputAdapter


def _import_tracker():
    try:
        from src.core.comprehensive_taint_tracking import ComprehensiveTaintTracker  # type: ignore

        return ComprehensiveTaintTracker
    except Exception:
        from core.comprehensive_taint_tracking import ComprehensiveTaintTracker  # type: ignore

        return ComprehensiveTaintTracker


def _import_cli_helpers():
    try:
        from src.core.bean_vuln_cli_enhanced import _normalize_jni_cli_args, _summarize_native_jni  # type: ignore

        return _normalize_jni_cli_args, _summarize_native_jni
    except Exception:
        from core.bean_vuln_cli_enhanced import _normalize_jni_cli_args, _summarize_native_jni  # type: ignore

        return _normalize_jni_cli_args, _summarize_native_jni


def test_jni_surface_detects_native_methods_and_libraries():
    JniSurfaceAnalyzer = _import_surface()

    code = "\n".join(
        [
            "package com.example;",
            "public class Foo {",
            "  static { System.loadLibrary(\"foo\"); }",
            "  public native String nativeEcho(String input);",
            "}",
        ]
    )

    analyzer = JniSurfaceAnalyzer()
    result = analyzer.analyze(code)
    methods = result.get("jni_methods", [])
    libs = result.get("jni_libraries", [])

    assert len(methods) == 1
    assert methods[0]["name"] == "nativeEcho"
    assert "foo" in libs


def test_native_binding_resolver_matches_native_root(tmp_path):
    NativeBindingResolver = _import_resolver()

    c_code = "\n".join(
        [
            "#include <jni.h>",
            "JNIEXPORT jstring JNICALL Java_com_example_Foo_nativeEcho(JNIEnv *env, jobject obj) {",
            "  return 0;",
            "}",
        ]
    )
    native_file = tmp_path / "native.c"
    native_file.write_text(c_code, encoding="utf-8")

    resolver = NativeBindingResolver(native_root=tmp_path)
    jni_methods = [
        {
            "name": "nativeEcho",
            "class_name": "Foo",
            "package": "com.example",
            "mangled_base": "Java_com_example_Foo_nativeEcho",
        }
    ]
    result = resolver.resolve(jni_methods)

    assert len(result.get("resolved", [])) == 1
    assert result["resolved"][0]["file"] == str(native_file)
    assert result["resolved"][0]["binding_type"] == "static"
    assert result["resolved"][0]["resolver"] == "source_scan"


def test_native_binding_resolver_merges_register_natives():
    NativeBindingResolver = _import_resolver()
    resolver = NativeBindingResolver(native_root=None)

    jni_methods = [
        {
            "name": "nativeEcho",
            "class_name": "Foo",
            "package": "com.example",
            "params": "String input",
            "mangled_base": "Java_com_example_Foo_nativeEcho",
        }
    ]
    dynamic_bindings = [
        {
            "java_name": "nativeEcho",
            "signature": "(Ljava/lang/String;)Ljava/lang/String;",
            "native_func": "nativeEchoImpl",
            "native_symbol": "nativeEchoImpl",
            "table": "methods",
            "line": 12,
            "file": "native.c",
            "confidence": "dynamic_registration",
        }
    ]

    result = resolver.resolve(jni_methods, dynamic_bindings=dynamic_bindings)
    resolved = result.get("resolved", [])

    assert any(item.get("binding_type") == "register_natives" for item in resolved)
    assert result.get("coverage", {}).get("register_natives", 0) >= 1


def test_native_binding_resolver_uses_symbol_scan_evidence():
    NativeBindingResolver = _import_resolver()
    resolver = NativeBindingResolver(native_root=None)

    jni_methods = [
        {
            "name": "nativeEcho",
            "class_name": "Foo",
            "package": "com.example",
            "params": "String input",
            "mangled_base": "Java_com_example_Foo_nativeEcho",
        }
    ]
    symbol_scan = {
        "binary": "/tmp/libfoo.so",
        "jni_symbols": ["Java_com_example_Foo_nativeEcho"],
    }
    result = resolver.resolve(jni_methods, symbol_scan=symbol_scan)
    resolved = result.get("resolved", [])

    assert any(item.get("resolver") == "symbol_table" for item in resolved)
    assert result.get("coverage", {}).get("static", 0) >= 1


def test_register_natives_parser_extracts_table_entries(tmp_path):
    RegisterNativesParser = _import_register_parser()
    parser = RegisterNativesParser()
    source = "\n".join(
        [
            '#include <jni.h>',
            'static jstring nativeEchoImpl(JNIEnv *env, jobject obj, jstring in) { return in; }',
            'JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {',
            '  JNIEnv *env = 0;',
            '  (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6);',
            '  jclass cls = (*env)->FindClass(env, "com/example/Foo");',
            '  JNINativeMethod methods[] = {',
            '    {"nativeEcho", "(Ljava/lang/String;)Ljava/lang/String;", (void*)nativeEchoImpl},',
            '  };',
            '  (*env)->RegisterNatives(env, cls, methods, 1);',
            '  return JNI_VERSION_1_6;',
            '}',
        ]
    )
    src_file = tmp_path / "native.c"
    src_file.write_text(source, encoding="utf-8")

    payload = parser.parse_file(src_file)
    entries = payload.get("entries", [])
    regs = payload.get("registrations", [])

    assert len(entries) == 1
    assert entries[0]["java_name"] == "nativeEcho"
    assert entries[0]["signature"] == "(Ljava/lang/String;)Ljava/lang/String;"
    assert entries[0]["class_descriptor"] == "com/example/Foo"
    assert entries[0]["resolver"] == "register_natives"
    assert len(regs) == 1


def test_invocation_analyzer_detects_invocation_and_callbacks(tmp_path):
    JniInvocationAnalyzer = _import_invocation_analyzer()
    analyzer = JniInvocationAnalyzer()
    source = "\n".join(
        [
            '#include <jni.h>',
            'int boot(JavaVM *vm) {',
            '  JNIEnv *env = 0;',
            '  (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6);',
            '  (*vm)->AttachCurrentThread(vm, (void **)&env, 0);',
            '  jclass c = (*env)->FindClass(env, "java/lang/String");',
            '  jmethodID m = (*env)->GetMethodID(env, c, "length", "()I");',
            '  (*env)->CallIntMethod(env, c, m);',
            '  return 0;',
            '}',
        ]
    )
    src_file = tmp_path / "invoke.c"
    src_file.write_text(source, encoding="utf-8")

    payload = analyzer.analyze_native_root(tmp_path)
    inv = payload.get("invocation_api_usage", {})
    cb = payload.get("callback_api_usage", {})

    assert inv.get("GetEnv", 0) >= 1
    assert inv.get("AttachCurrentThread", 0) >= 1
    assert cb.get("FindClass", 0) >= 1
    assert cb.get("GetMethodID", 0) >= 1
    assert cb.get("CallIntMethod", 0) >= 1


def test_phase2_crosslang_modules_produce_callgraph_and_summaries(tmp_path):
    NativeIRBuilder, CrossLanguagePointsToAnalyzer, NativeTaintSummaryBuilder = _import_crosslang_components()

    src = tmp_path / "jni_demo.c"
    src.write_text(
        "\n".join(
            [
                "#include <jni.h>",
                "static jint impl(JNIEnv *env, jobject obj, jstring cmd) {",
                "  const char* c = (*env)->GetStringUTFChars(env, cmd, 0);",
                "  system(c);",
                "  return 0;",
                "}",
                "static jint bridge(JNIEnv *env, jobject obj, jstring cmd) {",
                "  return impl(env, obj, cmd);",
                "}",
            ]
        ),
        encoding="utf-8",
    )

    builder = NativeIRBuilder()
    native_ir = builder.build(tmp_path)
    assert len(native_ir.get("functions", [])) >= 2

    points_to = CrossLanguagePointsToAnalyzer().analyze(
        resolved_bindings=[
            {
                "java_name": "nativeExecute",
                "native_func": "bridge",
                "resolver": "register_natives",
                "confidence": "dynamic_registration",
                "binding_type": "register_natives",
            }
        ],
        dynamic_registrations=[],
        native_ir=native_ir,
    )
    assert len(points_to.get("jni_call_graph", [])) >= 1
    assert points_to.get("jni_points_to", {}).get("java_to_native_bindings", {}).get("nativeExecute")

    summaries = NativeTaintSummaryBuilder().build(
        resolved_bindings=[
            {
                "java_name": "nativeExecute",
                "native_func": "bridge",
                "resolver": "register_natives",
                "binding_type": "register_natives",
                "signature": "(Ljava/lang/String;)I",
            }
        ],
        native_ir=native_ir,
        crosslang_points_to=points_to,
    )
    assert len(summaries.get("native_method_summaries", [])) >= 1


def test_taie_ingestor_and_svf_adapter_parse_artifacts(tmp_path):
    TaiEFactsIngestor, SvfOutputAdapter = _import_crosslang_fact_adapters()

    taie_path = tmp_path / "taie_facts.json"
    taie_path.write_text(
        """{
  "call_graph": [
    {"source": "java:nativeExecute", "target": "native:nativeExecuteImpl"}
  ],
  "points_to": {
    "java_to_native_bindings": {"nativeExecute": ["nativeExecuteImpl"]},
    "native_to_java_callbacks": {"nativeCallbackExecImpl": ["java:reflectiveSink"]}
  }
}""",
        encoding="utf-8",
    )
    svf_path = tmp_path / "svf_callgraph.dot"
    svf_path.write_text(
        "\n".join(
            [
                "digraph G {",
                '  "native:nativeExecuteImpl" -> "native:system";',
                '  "native:nativeReadFileImpl" -> "native:fopen";',
                "}",
            ]
        ),
        encoding="utf-8",
    )

    taie_payload = TaiEFactsIngestor().load(taie_path)
    svf_payload = SvfOutputAdapter().load(svf_path)

    assert taie_payload.get("loaded") is True
    assert len(taie_payload.get("call_graph", [])) >= 1
    assert "java_to_native_bindings" in taie_payload.get("points_to", {})
    assert svf_payload.get("loaded") is True
    assert len(svf_payload.get("call_graph", [])) >= 2


def test_jni_tracking_summary_mode_records_transfers():
    ComprehensiveTaintTracker = _import_tracker()

    code = "\n".join(
        [
            "package com.example;",
            "public class Foo {",
            "  public native String nativeEcho(String input);",
            "  public String m(String input) {",
            "    String out = nativeEcho(input);",
            "    return out;",
            "  }",
            "}",
        ]
    )

    tracker = ComprehensiveTaintTracker(
        enable_implicit_flows=False,
        enable_path_sensitive=False,
        enable_native_jni=True,
        jni_mode="summary",
    )
    result = tracker.analyze_java_code(code)
    native = result.get("native_code_analysis", {})

    assert int(native.get("jni_methods", 0)) == 1
    assert int(native.get("taint_transfers", 0)) >= 1
    assert native.get("analysis_mode") == "summary"


def test_jni_vuln_spectrum_has_dynamic_binding_and_risk_evidence():
    ComprehensiveTaintTracker = _import_tracker()

    sample_java = (
        Path(__file__).resolve().parent / "samples" / "jni_vuln_spectrum" / "JNI_Vuln_Spectrum.java"
    )
    sample_native = Path(__file__).resolve().parent / "samples" / "jni_vuln_spectrum" / "native"
    code = sample_java.read_text(encoding="utf-8")

    tracker = ComprehensiveTaintTracker(
        enable_implicit_flows=False,
        enable_path_sensitive=False,
        enable_native_jni=True,
        jni_mode="summary",
        jni_native_root=str(sample_native),
        jni_resolve_register_natives=True,
    )
    result = tracker.analyze_java_code(code)
    native = result.get("native_code_analysis", {})

    assert native.get("analysis_mode") == "summary"
    assert len(native.get("dynamic_registrations", [])) >= 1
    assert len(native.get("resolved_bindings", [])) >= 1
    assert native.get("binding_coverage", {}).get("register_natives", 0) >= 1
    assert native.get("invocation_api_usage", {}).get("GetEnv", 0) >= 1
    assert native.get("callback_api_usage", {}).get("FindClass", 0) >= 1
    risk_counts = native.get("native_risk_patterns", {}).get("counts", {})
    assert risk_counts.get("file_io_calls", 0) >= 1
    assert risk_counts.get("command_exec_calls", 0) >= 1


def test_jni_vuln_spectrum_crosslang_mode_emits_phase2_fields():
    ComprehensiveTaintTracker = _import_tracker()
    sample_java = (
        Path(__file__).resolve().parent / "samples" / "jni_vuln_spectrum" / "JNI_Vuln_Spectrum.java"
    )
    sample_native = Path(__file__).resolve().parent / "samples" / "jni_vuln_spectrum" / "native"
    compile_commands = sample_native / "compile_commands.json"
    code = sample_java.read_text(encoding="utf-8")

    tracker = ComprehensiveTaintTracker(
        enable_implicit_flows=False,
        enable_path_sensitive=False,
        enable_native_jni=True,
        jni_mode="crosslang",
        jni_native_root=str(sample_native),
        jni_compile_commands=str(compile_commands),
        jni_resolve_register_natives=True,
    )
    result = tracker.analyze_java_code(code)
    native = result.get("native_code_analysis", {})

    assert native.get("analysis_mode") == "crosslang"
    assert len(native.get("jni_call_graph", [])) >= 1
    assert isinstance(native.get("jni_points_to", {}), dict)
    assert len(native.get("native_method_summaries", [])) >= 1
    assert native.get("cross_language_backend")
    assert native.get("compile_commands_used") is True


def test_jni_vuln_spectrum_taie_svf_backend_emits_fused_fields():
    ComprehensiveTaintTracker = _import_tracker()
    sample_java = (
        Path(__file__).resolve().parent / "samples" / "jni_vuln_spectrum" / "JNI_Vuln_Spectrum.java"
    )
    sample_native = Path(__file__).resolve().parent / "samples" / "jni_vuln_spectrum" / "native"
    compile_commands = sample_native / "compile_commands.json"
    taie_facts = sample_native / "taie_facts.json"
    svf_output = sample_native / "svf_output.json"
    code = sample_java.read_text(encoding="utf-8")

    tracker = ComprehensiveTaintTracker(
        enable_implicit_flows=False,
        enable_path_sensitive=False,
        enable_native_jni=True,
        jni_mode="crosslang",
        jni_native_root=str(sample_native),
        jni_compile_commands=str(compile_commands),
        jni_resolve_register_natives=True,
        jni_crosslang_backend="taie_svf",
        jni_taie_facts=str(taie_facts),
        jni_svf_output=str(svf_output),
    )
    result = tracker.analyze_java_code(code)
    native = result.get("native_code_analysis", {})

    assert native.get("cross_language_backend_requested") == "taie_svf"
    assert native.get("cross_language_backend") == "taie_svf-v1"
    assert native.get("cross_language_status") == "ok"
    assert native.get("crosslang_impact", {}).get("available") is True
    assert "delta" in native.get("crosslang_impact", {})
    assert native.get("taie_facts", {}).get("loaded") is True
    assert native.get("svf_output", {}).get("loaded") is True
    assert len(native.get("jni_call_graph", [])) >= 1


def test_jni_vuln_spectrum_taie_svf_missing_artifacts_falls_back_when_not_strict():
    ComprehensiveTaintTracker = _import_tracker()
    sample_java = (
        Path(__file__).resolve().parent / "samples" / "jni_vuln_spectrum" / "JNI_Vuln_Spectrum.java"
    )
    sample_native = Path(__file__).resolve().parent / "samples" / "jni_vuln_spectrum" / "native"
    code = sample_java.read_text(encoding="utf-8")

    tracker = ComprehensiveTaintTracker(
        enable_implicit_flows=False,
        enable_path_sensitive=False,
        enable_native_jni=True,
        jni_mode="crosslang",
        jni_native_root=str(sample_native),
        jni_resolve_register_natives=True,
        jni_crosslang_backend="taie_svf",
        jni_taie_facts=str(sample_native / "missing_taie.json"),
        jni_svf_output=str(sample_native / "missing_svf.json"),
    )
    result = tracker.analyze_java_code(code)
    native = result.get("native_code_analysis", {})

    assert native.get("cross_language_backend_requested") == "taie_svf"
    assert native.get("cross_language_backend") == "heuristic-crosslang-v1"
    assert native.get("cross_language_status") == "degraded_fallback"
    assert native.get("crosslang_impact", {}).get("available") is False
    assert native.get("crosslang_impact", {}).get("status") == "degraded_fallback"
    assert any("taie:taie_facts_not_found" in str(err) for err in native.get("errors", []))


def test_jni_vuln_spectrum_taie_svf_fail_closed_raises_without_artifacts():
    ComprehensiveTaintTracker = _import_tracker()
    sample_java = (
        Path(__file__).resolve().parent / "samples" / "jni_vuln_spectrum" / "JNI_Vuln_Spectrum.java"
    )
    sample_native = Path(__file__).resolve().parent / "samples" / "jni_vuln_spectrum" / "native"
    code = sample_java.read_text(encoding="utf-8")

    tracker = ComprehensiveTaintTracker(
        enable_implicit_flows=False,
        enable_path_sensitive=False,
        enable_native_jni=True,
        jni_mode="crosslang",
        jni_native_root=str(sample_native),
        jni_resolve_register_natives=True,
        jni_crosslang_backend="taie_svf",
        jni_taie_facts=str(sample_native / "missing_taie.json"),
        jni_svf_output=str(sample_native / "missing_svf.json"),
        jni_fail_closed=True,
    )

    raised = False
    try:
        tracker.analyze_java_code(code)
    except RuntimeError:
        raised = True
    assert raised is True


def test_jni_cli_spectrum_mode_normalizes_and_autodetects_root(tmp_path):
    normalize_args, _ = _import_cli_helpers()

    java_file = tmp_path / "Foo.java"
    java_file.write_text("public class Foo {}", encoding="utf-8")
    native_dir = tmp_path / "native"
    native_dir.mkdir(parents=True, exist_ok=True)
    (native_dir / "foo.c").write_text("int x = 0;", encoding="utf-8")

    args = argparse.Namespace(
        native_jni=True,
        jni_spectrum=True,
        jni_mode="heuristic",
        jni_resolve_register_natives=False,
        jni_disable_callbacks=True,
        taint_graph=False,
        jni_native_root=None,
        jni_compile_commands=None,
        jni_binary=None,
        jni_symbol_tool=None,
        input=[str(java_file)],
    )
    normalize_args(args)

    assert args.jni_mode == "summary"
    assert args.jni_resolve_register_natives is True
    assert args.jni_disable_callbacks is False
    assert args.taint_graph is True
    assert args.jni_native_root == str(native_dir)


def test_jni_cli_crosslang_autodetects_compile_commands(tmp_path):
    normalize_args, _ = _import_cli_helpers()
    java_file = tmp_path / "Foo.java"
    java_file.write_text("public class Foo {}", encoding="utf-8")
    native_dir = tmp_path / "native"
    native_dir.mkdir(parents=True, exist_ok=True)
    (native_dir / "foo.c").write_text("int x = 0;", encoding="utf-8")
    compile_db = native_dir / "compile_commands.json"
    compile_db.write_text(
        '[{"directory": ".", "file": "native/foo.c", "command": "clang -c native/foo.c -o foo.o"}]',
        encoding="utf-8",
    )
    taie_facts = native_dir / "taie_facts.json"
    taie_facts.write_text('{"call_graph": [], "points_to": {}}', encoding="utf-8")
    svf_output = native_dir / "svf_output.json"
    svf_output.write_text('{"native_call_graph": [], "points_to": {}}', encoding="utf-8")

    args = argparse.Namespace(
        native_jni=True,
        jni_spectrum=False,
        jni_mode="crosslang",
        jni_crosslang_backend="auto",
        jni_resolve_register_natives=False,
        jni_disable_callbacks=True,
        taint_graph=False,
        jni_native_root=str(native_dir),
        jni_compile_commands=None,
        jni_taie_facts=None,
        jni_svf_output=None,
        jni_fail_closed=False,
        jni_binary=None,
        jni_symbol_tool=None,
        input=[str(java_file)],
    )
    normalize_args(args)

    assert args.jni_mode == "crosslang"
    assert args.jni_compile_commands == str(compile_db)
    assert args.jni_taie_facts == str(taie_facts)
    assert args.jni_svf_output == str(svf_output)
    assert args.jni_disable_callbacks is False
    assert args.jni_resolve_register_natives is True


def test_jni_cli_fail_closed_rejects_missing_taie_svf_artifacts(tmp_path):
    normalize_args, _ = _import_cli_helpers()
    java_file = tmp_path / "Foo.java"
    java_file.write_text("public class Foo {}", encoding="utf-8")
    native_dir = tmp_path / "native"
    native_dir.mkdir(parents=True, exist_ok=True)
    (native_dir / "foo.c").write_text("int x = 0;", encoding="utf-8")

    args = argparse.Namespace(
        native_jni=True,
        jni_spectrum=False,
        jni_mode="crosslang",
        jni_crosslang_backend="taie_svf",
        jni_resolve_register_natives=False,
        jni_disable_callbacks=True,
        taint_graph=False,
        jni_native_root=str(native_dir),
        jni_compile_commands=None,
        jni_taie_facts=None,
        jni_svf_output=None,
        jni_fail_closed=True,
        jni_binary=None,
        jni_symbol_tool=None,
        input=[str(java_file)],
    )

    raised = False
    try:
        normalize_args(args)
    except ValueError:
        raised = True
    assert raised is True


def test_jni_summary_helper_reports_expected_fields():
    _, summarize_native = _import_cli_helpers()
    payload = {
        "analysis_mode": "summary",
        "jni_methods": 3,
        "taint_transfers": 4,
        "resolved_bindings": [{"java_name": "a"}],
        "unresolved_bindings": [{"java_name": "b"}],
        "dynamic_registrations": [{"java_name": "a"}, {"java_name": "c"}],
        "binding_coverage": {"register_natives": 1},
        "invocation_api_usage": {"GetEnv": 2},
        "callback_api_usage": {"FindClass": 1},
        "native_risk_patterns": {"counts": {"file_io_calls": 2, "command_exec_calls": 1}},
        "jni_libraries": ["foo"],
        "symbol_scan": {"symbol_tool": "nm", "jni_symbols": ["Java_a"]},
        "jni_call_graph": [{"source": "java:a", "target": "native:b"}],
        "native_method_summaries": [{"java_method": "a"}],
        "cross_language_backend_requested": "auto",
        "cross_language_backend": "heuristic-crosslang-v1",
        "cross_language_status": "ok",
        "crosslang_impact": {
            "available": True,
            "status": "ok",
            "baseline": {"jni_call_graph_edges": 3, "points_to_bindings": 2, "native_method_summaries": 1},
            "effective": {"jni_call_graph_edges": 5, "points_to_bindings": 3, "native_method_summaries": 2},
            "delta": {"jni_call_graph_edges": 2, "points_to_bindings": 1, "native_method_summaries": 1},
        },
        "compile_commands_used": True,
        "taie_facts": {"loaded": True, "source_path": "/tmp/taie.json"},
        "svf_output": {"loaded": True, "source_path": "/tmp/svf.json"},
    }
    summary = summarize_native(payload)

    assert summary["mode"] == "summary"
    assert summary["jni_methods"] == 3
    assert summary["taint_transfers"] == 4
    assert summary["resolved_bindings"] == 1
    assert summary["unresolved_bindings"] == 1
    assert summary["dynamic_registrations"] == 2
    assert summary["risk_total"] == 3
    assert summary["symbol_hits"] == 1
    assert summary["jni_call_graph_edges"] == 1
    assert summary["native_method_summaries"] == 1
    assert summary["cross_language_backend_requested"] == "auto"
    assert summary["cross_language_backend"] == "heuristic-crosslang-v1"
    assert summary["cross_language_status"] == "ok"
    assert summary["impact_available"] is True
    assert summary["impact_delta"]["jni_call_graph_edges"] == 2
    assert summary["compile_commands_used"] is True
    assert summary["taie_facts_loaded"] is True
    assert summary["svf_output_loaded"] is True
