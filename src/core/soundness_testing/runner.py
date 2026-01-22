"""Run runtime soundness validation for Tai-e results."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
import re
import subprocess
import tempfile
import os

from .java_instrumenter import JavaValueInstrumenter
from .soundness_validator import SoundnessValidator

PACKAGE_RE = re.compile(r'^\s*package\s+([\w.]+)\s*;', re.MULTILINE)
CLASS_RE = re.compile(r'\bclass\s+(\w+)\b')
PUBLIC_METHOD_RE = re.compile(
    r'^\s*(public|protected)\s+(static\s+)?(?!class\b|interface\b|enum\b)'
    r'([\w<>\[\],\s]+)\s+(\w+)\s*\(([^)]*)\)',
    re.MULTILINE,
)
MAIN_RE = re.compile(r'public\s+static\s+void\s+main\s*\(\s*String\s*\[\]\s*\w*\s*\)')


@dataclass
class SoundnessResult:
    success: bool
    report_path: Optional[str]
    error: Optional[str]
    report: Optional[Dict[str, Any]]


def run_soundness_validation(
    source_path: Path,
    points_to_file: Path,
    classpath: Optional[str] = None,
    output_dir: Optional[Path] = None,
    report_path: Optional[Path] = None,
) -> SoundnessResult:
    if not points_to_file or not points_to_file.exists():
        return SoundnessResult(False, None, "points_to_file_missing", None)

    output_dir = output_dir or (Path.cwd() / "analysis")
    output_dir.mkdir(parents=True, exist_ok=True)

    source_code = source_path.read_text(encoding="utf-8", errors="ignore")
    package_name = _extract_package(source_code)
    class_name = _extract_class(source_code, source_path)
    if not class_name:
        return SoundnessResult(False, None, "class_name_not_found", None)

    with tempfile.TemporaryDirectory() as tmpdir:
        base_dir = Path(tmpdir)
        src_dir = base_dir / "src"
        classes_dir = base_dir / "classes"
        src_dir.mkdir(parents=True, exist_ok=True)
        classes_dir.mkdir(parents=True, exist_ok=True)

        instrumenter = JavaValueInstrumenter()
        instrumenter.instrument(source_path, src_dir)

        main_class, wrapper_written = _ensure_entrypoint(src_dir, package_name, class_name, source_code)
        if not main_class:
            return SoundnessResult(False, None, "main_class_missing", None)

        compile_err = _compile_sources(src_dir, classes_dir, classpath)
        if compile_err:
            return SoundnessResult(False, None, f"javac_failed:{compile_err}", None)

        run_err = _run_java(classes_dir, main_class, classpath)
        if run_err:
            return SoundnessResult(False, None, f"java_failed:{run_err}", None)

        log_file = classes_dir / "value_log.json"
        if not log_file.exists():
            return SoundnessResult(False, None, "value_log_missing", None)

        report_path = report_path or (output_dir / f"soundness_report_{class_name}.html")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        validator = SoundnessValidator(points_to_file, log_file)
        report = validator.generate_html_report(report_path).to_dict()

        report["entrypoint_wrapper"] = wrapper_written

        return SoundnessResult(True, str(report_path), None, report)


def _extract_package(source: str) -> Optional[str]:
    match = PACKAGE_RE.search(source)
    return match.group(1) if match else None


def _extract_class(source: str, source_path: Path) -> Optional[str]:
    match = CLASS_RE.search(source)
    if match:
        return match.group(1)
    return source_path.stem


def _ensure_entrypoint(
    src_dir: Path, package_name: Optional[str], class_name: str, source_code: str
) -> Tuple[Optional[str], bool]:
    if MAIN_RE.search(source_code):
        return _fqn(package_name, class_name), False

    wrapper_name = "BeanVulnSoundnessEntryPoint"
    methods = _extract_public_methods(source_code, class_name)
    calls = []
    for method_name, is_static, param_types in methods:
        args = ", ".join(_default_value_for_type(t) for t in param_types)
        if is_static:
            calls.append(f"        {class_name}.{method_name}({args});")
        else:
            calls.append(f"        target.{method_name}({args});")

    if not calls:
        calls.append("        // No public methods detected")

    lines = []
    if package_name:
        lines.append(f"package {package_name};")
        lines.append("")
    lines.append(f"public class {wrapper_name} {{")
    lines.append("    public static void main(String[] args) throws Exception {")
    lines.append('        ValueLogger.log("__soundness__", "start");')
    lines.append(f"        {class_name} target = new {class_name}();")
    lines.extend(calls)
    lines.append("    }")
    lines.append("}")

    if package_name:
        pkg_dir = src_dir / Path(package_name.replace(".", "/"))
        pkg_dir.mkdir(parents=True, exist_ok=True)
    else:
        pkg_dir = src_dir
    wrapper_path = pkg_dir / f"{wrapper_name}.java"
    wrapper_path.write_text("\n".join(lines), encoding="utf-8")
    return _fqn(package_name, wrapper_name), True


def _extract_public_methods(source: str, class_name: str) -> List[Tuple[str, bool, List[str]]]:
    methods = []
    for match in PUBLIC_METHOD_RE.finditer(source):
        is_static = bool(match.group(2))
        method_name = match.group(4)
        params = match.group(5).strip()
        if method_name == class_name or method_name == "main":
            continue
        param_types = _parse_param_types(params)
        methods.append((method_name, is_static, param_types))
    return methods


def _parse_param_types(params: str) -> List[str]:
    if not params:
        return []
    parts = [p.strip() for p in params.split(",") if p.strip()]
    types = []
    for part in parts:
        part = re.sub(r'@\w+(?:\([^)]*\))?\s*', '', part)
        part = part.replace("final ", "").strip()
        tokens = part.split()
        if len(tokens) < 2:
            continue
        type_str = " ".join(tokens[:-1]).strip()
        if type_str:
            types.append(type_str)
    return types


def _default_value_for_type(type_str: str) -> str:
    raw = type_str.strip()
    if raw.endswith("...") or raw.endswith("[]"):
        return "null"
    cleaned = re.sub(r"<.*?>", "", raw).strip()
    base = cleaned.split()[-1] if cleaned else raw
    base = base.split(".")[-1]
    primitive_defaults = {
        "byte": "(byte)0",
        "short": "(short)0",
        "int": "0",
        "long": "0L",
        "float": "0.0f",
        "double": "0.0d",
        "boolean": "false",
        "char": "'\\0'",
    }
    if base in primitive_defaults:
        return primitive_defaults[base]
    if base == "String":
        return "\"\""
    return "null"


def _compile_sources(src_dir: Path, classes_dir: Path, classpath: Optional[str]) -> Optional[str]:
    sources = sorted(src_dir.rglob("*.java"))
    if not sources:
        return "no_sources"
    cmd = ["javac", "-d", str(classes_dir)]
    if classpath:
        cmd.extend(["-cp", classpath])
    cmd.extend([str(source) for source in sources])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except Exception as exc:
        return str(exc)
    if result.returncode != 0:
        return result.stderr.strip() or result.stdout.strip() or "javac_failed"
    return None


def _run_java(classes_dir: Path, main_class: str, classpath: Optional[str]) -> Optional[str]:
    cp_entries = [str(classes_dir)]
    if classpath:
        for entry in classpath.split(os.pathsep):
            if entry.strip():
                cp_entries.append(str(Path(entry).expanduser().resolve()))
    cp = os.pathsep.join(cp_entries)
    cmd = ["java", "-cp", cp, main_class]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, cwd=str(classes_dir))
    except Exception as exc:
        return str(exc)
    if result.returncode != 0:
        return result.stderr.strip() or result.stdout.strip() or "java_failed"
    return None


def _fqn(package_name: Optional[str], class_name: str) -> str:
    return f"{package_name}.{class_name}" if package_name else class_name
