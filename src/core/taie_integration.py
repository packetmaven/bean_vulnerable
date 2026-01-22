"""
Tai-e integration for object-sensitive pointer/alias analysis.

This module runs Tai-e on compiled Java bytecode and extracts coarse
points-to statistics for reporting in alias_analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
import logging
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime

try:
    import yaml  # type: ignore
    YAML_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    yaml = None
    YAML_AVAILABLE = False

LOG = logging.getLogger(__name__)

PACKAGE_RE = re.compile(r'^\s*package\s+([\w.]+)\s*;', re.MULTILINE)
PUBLIC_CLASS_RE = re.compile(r'public\s+(?:final\s+|abstract\s+)?class\s+(\w+)\b')
CLASS_RE = re.compile(r'\bclass\s+(\w+)\b')
MAIN_RE = re.compile(r'public\s+static\s+void\s+main\s*\(\s*String\s*\[\]\s*\w*\s*\)')
METHOD_RE = re.compile(
    r'^\s*(public|protected)\s+(static\s+)?(?!class\b|interface\b|enum\b)'
    r'([\w<>\[\],\s]+)\s+(\w+)\s*\(([^)]*)\)',
    re.MULTILINE,
)


@dataclass
class TaiEConfig:
    enabled: bool = False
    tai_e_home: Optional[str] = None
    cs: str = "1-obj"
    main_class: Optional[str] = None
    timeout: Optional[int] = 300
    only_app: bool = True
    implicit_entries: bool = True
    allow_phantom: bool = True
    prepend_jvm: bool = True
    java_version: Optional[int] = None
    classpath: Optional[str] = None
    enable_taint: bool = False
    taint_config: Optional[str] = None


@dataclass
class TaiEResult:
    enabled: bool
    success: bool
    object_sensitive: bool
    cs: str
    main_class: Optional[str]
    output_dir: Optional[str]
    points_to_file: Optional[str]
    variable_to_allocation_mappings: Optional[int]
    allocation_sites: Optional[int]
    library_summaries_loaded: Optional[int]
    errors: List[str]
    synthetic_entrypoint: bool = False
    taint_enabled: bool = False
    taint_config: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TaiEIntegration:
    def __init__(self, config: TaiEConfig) -> None:
        self.config = config

    def run(self, source_code: str, source_path: Optional[str]) -> TaiEResult:
        if not self.config.enabled:
            return TaiEResult(
                enabled=False,
                success=False,
                object_sensitive=False,
                cs=self.config.cs,
                main_class=None,
                output_dir=None,
                points_to_file=None,
                variable_to_allocation_mappings=None,
                allocation_sites=None,
                library_summaries_loaded=None,
                errors=["tai_e_disabled"],
            )

        tai_e_home = self._resolve_tai_e_home()
        jar_path = self._find_tai_e_jar(tai_e_home)
        if not jar_path:
            return TaiEResult(
                enabled=True,
                success=False,
                object_sensitive=False,
                cs=self.config.cs,
                main_class=None,
                output_dir=None,
                points_to_file=None,
                variable_to_allocation_mappings=None,
                allocation_sites=None,
                library_summaries_loaded=None,
                errors=["tai_e_jar_not_found"],
                taint_enabled=bool(self.config.enable_taint or self.config.taint_config),
                taint_config=self.config.taint_config,
            )

        package_name, class_name = self._extract_package_and_class(source_code, source_path)
        if not class_name:
            return TaiEResult(
                enabled=True,
                success=False,
                object_sensitive=False,
                cs=self.config.cs,
                main_class=None,
                output_dir=None,
                points_to_file=None,
                variable_to_allocation_mappings=None,
                allocation_sites=None,
                library_summaries_loaded=None,
                errors=["class_name_not_found"],
                taint_enabled=bool(self.config.enable_taint or self.config.taint_config),
                taint_config=self.config.taint_config,
            )

        main_class = self.config.main_class
        synthetic_entrypoint = False

        repo_root = Path(__file__).resolve().parents[2]
        runs_root = repo_root / "analysis" / "tai_e_runs"
        runs_root.mkdir(parents=True, exist_ok=True)
        run_tag = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_class = main_class.replace(".", "_") if main_class else "unknown"
        persistent_output = runs_root / f"{run_tag}_{safe_class}"
        persistent_output.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = Path(tmpdir)
            src_dir = base_dir / "src"
            classes_dir = base_dir / "classes"
            output_dir = persistent_output
            src_dir.mkdir(parents=True, exist_ok=True)
            classes_dir.mkdir(parents=True, exist_ok=True)

            self._write_source_file(
                src_dir, package_name, class_name, source_code, source_path
            )
            if not main_class:
                if MAIN_RE.search(source_code):
                    main_class = self._fqn(package_name, class_name)
                else:
                    main_class = self._write_entrypoint_wrapper(
                        src_dir, package_name, class_name, source_code
                    )
                    synthetic_entrypoint = True

            taint_config = self._resolve_taint_config()
            if (self.config.enable_taint or taint_config) and not taint_config:
                return TaiEResult(
                    enabled=True,
                    success=False,
                    object_sensitive=False,
                    cs=self.config.cs,
                    main_class=main_class,
                    output_dir=str(output_dir),
                    points_to_file=None,
                    variable_to_allocation_mappings=None,
                    allocation_sites=None,
                    library_summaries_loaded=None,
                    errors=["tai_e_taint_config_missing"],
                    synthetic_entrypoint=synthetic_entrypoint,
                    taint_enabled=True,
                    taint_config=None,
                )

            compile_errors = self._compile_sources(src_dir, classes_dir)
            if compile_errors:
                return TaiEResult(
                    enabled=True,
                    success=False,
                    object_sensitive=False,
                    cs=self.config.cs,
                    main_class=main_class,
                    output_dir=str(output_dir),
                    points_to_file=None,
                    variable_to_allocation_mappings=None,
                    allocation_sites=None,
                    library_summaries_loaded=None,
                    errors=compile_errors,
                    synthetic_entrypoint=synthetic_entrypoint,
                    taint_enabled=bool(self.config.enable_taint or taint_config),
                    taint_config=str(taint_config) if taint_config else None,
                )

            tai_e_errors = self._run_tai_e(
                jar_path=jar_path,
                classes_dir=classes_dir,
                main_class=main_class,
                output_dir=output_dir,
                taint_config=taint_config,
            )
            if tai_e_errors:
                return TaiEResult(
                    enabled=True,
                    success=False,
                    object_sensitive=False,
                    cs=self.config.cs,
                    main_class=main_class,
                    output_dir=str(output_dir),
                    points_to_file=None,
                    variable_to_allocation_mappings=None,
                    allocation_sites=None,
                    library_summaries_loaded=None,
                    errors=tai_e_errors,
                    synthetic_entrypoint=synthetic_entrypoint,
                    taint_enabled=bool(self.config.enable_taint or taint_config),
                    taint_config=str(taint_config) if taint_config else None,
                )

            points_file, stats = self._extract_points_to_stats(output_dir)
            object_sensitive = "obj" in self.config.cs
            return TaiEResult(
                enabled=True,
                success=True,
                object_sensitive=object_sensitive,
                cs=self.config.cs,
                main_class=main_class,
                output_dir=str(output_dir),
                points_to_file=str(points_file) if points_file else None,
                variable_to_allocation_mappings=stats.get("variable_to_allocation_mappings"),
                allocation_sites=stats.get("allocation_sites"),
                library_summaries_loaded=None,
                errors=[],
                synthetic_entrypoint=synthetic_entrypoint,
                taint_enabled=bool(self.config.enable_taint or taint_config),
                taint_config=str(taint_config) if taint_config else None,
            )

    def _resolve_tai_e_home(self) -> Optional[Path]:
        if self.config.tai_e_home:
            return Path(self.config.tai_e_home).expanduser()
        env_home = os.getenv("TAI_E_HOME")
        if env_home:
            return Path(env_home).expanduser()
        return None

    def _find_tai_e_jar(self, tai_e_home: Optional[Path]) -> Optional[Path]:
        if not tai_e_home:
            return None
        if not tai_e_home.exists():
            return None
        if tai_e_home.is_file() and tai_e_home.suffix == ".jar":
            return tai_e_home
        candidates = list(tai_e_home.glob("**/*.jar"))
        if not candidates:
            return None
        for name in ("tai-e-all.jar", "tai-e.jar"):
            for path in candidates:
                if path.name == name:
                    return path
        # Fallback: largest jar
        return max(candidates, key=lambda p: p.stat().st_size)

    def _resolve_taint_config(self) -> Optional[Path]:
        if not (self.config.enable_taint or self.config.taint_config):
            return None
        if not self.config.taint_config:
            return None
        path = Path(self.config.taint_config).expanduser()
        if not path.exists():
            return None
        return path.resolve()

    def _extract_package_and_class(
        self, source_code: str, source_path: Optional[str]
    ) -> Tuple[Optional[str], Optional[str]]:
        package_match = PACKAGE_RE.search(source_code)
        package_name = package_match.group(1) if package_match else None

        class_match = PUBLIC_CLASS_RE.search(source_code)
        if not class_match:
            class_match = CLASS_RE.search(source_code)
        class_name = class_match.group(1) if class_match else None

        if not class_name and source_path:
            class_name = Path(source_path).stem

        return package_name, class_name

    def _fqn(self, package_name: Optional[str], class_name: str) -> str:
        return f"{package_name}.{class_name}" if package_name else class_name

    def _write_source_file(
        self,
        src_dir: Path,
        package_name: Optional[str],
        class_name: str,
        source_code: str,
        source_path: Optional[str],
    ) -> Path:
        if package_name:
            pkg_dir = src_dir / Path(package_name.replace(".", "/"))
            pkg_dir.mkdir(parents=True, exist_ok=True)
        else:
            pkg_dir = src_dir

        filename = f"{class_name}.java"
        if source_path and Path(source_path).name.endswith(".java"):
            filename = Path(source_path).name
        source_file = pkg_dir / filename
        source_file.write_text(source_code, encoding="utf-8")
        return source_file

    def _write_entrypoint_wrapper(
        self, src_dir: Path, package_name: Optional[str], class_name: str, source_code: str
    ) -> str:
        wrapper_name = "BeanVulnTaiEEntryPoint"
        if re.search(rf'\bclass\s+{re.escape(wrapper_name)}\b', source_code):
            wrapper_name = "BeanVulnTaiEEntryPointGenerated"

        methods = self._extract_public_methods(source_code, class_name)
        calls = []
        for method_name, is_static, param_types in methods:
            args = ", ".join(self._default_value_for_type(t) for t in param_types)
            if is_static:
                calls.append(f"        {class_name}.{method_name}({args});")
            else:
                calls.append(f"        target.{method_name}({args});")

        if not calls:
            calls.append("        // No public methods detected; instantiate class for reachability")

        lines = []
        if package_name:
            lines.append(f"package {package_name};")
            lines.append("")
        lines.append(f"public class {wrapper_name} {{")
        lines.append("    public static void main(String[] args) throws Exception {")
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
        return self._fqn(package_name, wrapper_name)

    def _extract_public_methods(
        self, source_code: str, class_name: str
    ) -> List[Tuple[str, bool, List[str]]]:
        methods = []
        for match in METHOD_RE.finditer(source_code):
            is_static = bool(match.group(2))
            method_name = match.group(4)
            params = match.group(5).strip()
            if method_name == class_name or method_name == "main":
                continue
            param_types = self._parse_param_types(params)
            methods.append((method_name, is_static, param_types))
        return methods

    def _parse_param_types(self, params: str) -> List[str]:
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

    def _default_value_for_type(self, type_str: str) -> str:
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

    def _compile_sources(self, src_dir: Path, classes_dir: Path) -> List[str]:
        sources = sorted(src_dir.rglob("*.java"))
        if not sources:
            return ["javac_no_sources"]
        cmd = ["javac", "-d", str(classes_dir)]
        if self.config.java_version:
            cmd.extend(["--release", str(self.config.java_version)])
        if self.config.classpath:
            cmd.extend(["-cp", self.config.classpath])
        cmd.extend([str(source) for source in sources])
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except Exception as exc:
            return [f"javac_failed:{exc}"]

        if result.returncode != 0:
            return [result.stderr.strip() or result.stdout.strip() or "javac_failed"]
        return []

    def _run_tai_e(
        self,
        jar_path: Path,
        classes_dir: Path,
        main_class: str,
        output_dir: Path,
        taint_config: Optional[Path] = None,
    ) -> List[str]:
        analysis_opts = [
            f"pta=cs:{self.config.cs}",
            "dump-yaml:true",
            f"only-app:{str(self.config.only_app).lower()}",
            f"implicit-entries:{str(self.config.implicit_entries).lower()}",
        ]
        if taint_config:
            analysis_opts.append(f"taint-config:{taint_config}")
        if self.config.timeout is not None:
            analysis_opts.append(f"time-limit:{int(self.config.timeout)}")

        cmd = ["java", "-jar", str(jar_path)]
        cmd.extend(["-cp", str(classes_dir)])
        cmd.extend(["-m", main_class])
        if self.config.java_version is not None:
            cmd.extend(["-java", str(self.config.java_version)])
        if self.config.prepend_jvm:
            cmd.append("--prepend-JVM")
        if self.config.allow_phantom:
            cmd.append("--allow-phantom")
        cmd.extend(["--output-dir", str(output_dir)])
        cmd.extend(["-a", ";".join(analysis_opts)])

        LOG.info("Tai-e command: %s", " ".join(cmd))
        tai_e_cwd = jar_path.parent
        if (jar_path.parent / "java-benchmarks").exists():
            tai_e_cwd = jar_path.parent
        elif (jar_path.parent.parent / "java-benchmarks").exists():
            tai_e_cwd = jar_path.parent.parent
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout or 600,
                cwd=str(tai_e_cwd),
            )
        except Exception as exc:
            return [f"tai_e_failed:{exc}"]

        (output_dir / "tai-e.stdout").write_text(result.stdout, encoding="utf-8")
        (output_dir / "tai-e.stderr").write_text(result.stderr, encoding="utf-8")

        if result.returncode != 0:
            return [result.stderr.strip() or result.stdout.strip() or "tai_e_failed"]
        return []

    def _extract_points_to_stats(self, output_dir: Path) -> Tuple[Optional[Path], Dict[str, Optional[int]]]:
        stats: Dict[str, Optional[int]] = {
            "variable_to_allocation_mappings": None,
            "allocation_sites": None,
        }
        candidates = []
        for ext in ("*.yml", "*.yaml"):
            for path in output_dir.rglob(ext):
                if path.name in {"options.yml", "tai-e-plan.yml"}:
                    continue
                candidates.append(path)

        if not candidates:
            return None, stats

        points_file = max(candidates, key=lambda p: p.stat().st_size)
        text = points_file.read_text(encoding="utf-8", errors="ignore")
        if YAML_AVAILABLE:
            try:
                payload = yaml.safe_load(text)
                pointer_count, allocs = self._parse_points_to_payload(payload)
                if pointer_count is not None:
                    stats["variable_to_allocation_mappings"] = pointer_count
                if allocs:
                    stats["allocation_sites"] = len(allocs)
                return points_file, stats
            except Exception:
                pass

        # Fallback regex scan
        allocation_hits = set(re.findall(r'alloc(?:ation)?\s*:\s*([^\n\r]+)', text))
        pointer_hits = re.findall(r'pointer\s*:', text)
        if allocation_hits:
            stats["allocation_sites"] = len(allocation_hits)
        if pointer_hits:
            stats["variable_to_allocation_mappings"] = len(pointer_hits)
        return points_file, stats

    def _parse_points_to_payload(self, payload: Any) -> Tuple[Optional[int], set]:
        pointer_entries: List[Any] = []

        def walk(obj: Any) -> None:
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key in {"pointsTo", "points-to", "points_to"} and isinstance(value, list):
                        pointer_entries.extend(value)
                    else:
                        walk(value)
            elif isinstance(obj, list):
                for item in obj:
                    walk(item)

        walk(payload)
        if not pointer_entries:
            return None, set()

        allocation_ids = set()
        pointer_count = 0
        for entry in pointer_entries:
            if not isinstance(entry, dict):
                continue
            pts = entry.get("pointsTo") or entry.get("points-to") or entry.get("points_to") or entry.get("pts")
            if not isinstance(pts, list):
                continue
            if pts:
                pointer_count += 1
            for obj in pts:
                if isinstance(obj, dict):
                    allocation = obj.get("allocation") or obj.get("alloc")
                    if allocation:
                        allocation_ids.add(str(allocation))
                    inner = obj.get("obj")
                    if isinstance(inner, dict):
                        allocation = inner.get("allocation") or inner.get("alloc")
                        if allocation:
                            allocation_ids.add(str(allocation))

        return pointer_count, allocation_ids
