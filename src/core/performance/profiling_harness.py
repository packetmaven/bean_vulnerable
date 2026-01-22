"""Multi-layer profiling harness for Tai-e runs (best-effort)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging
import re
import shutil
import subprocess
import tempfile
import time
import os

try:
    import psutil  # type: ignore
    PSUTIL_AVAILABLE = True
except Exception:
    psutil = None
    PSUTIL_AVAILABLE = False

from core.taie_integration import TaiEConfig, TaiEIntegration, MAIN_RE

logger = logging.getLogger(__name__)


@dataclass
class ProfilingConfiguration:
    enable_cpu_profiling: bool = False
    enable_memory_profiling: bool = False
    enable_tai_e_profiling: bool = False
    enable_system_profiling: bool = False
    enable_jfr: bool = False
    enable_heapdump: bool = False

    async_profiler_path: Optional[Path] = None
    yourkit_agent_path: Optional[Path] = None

    cpu_sampling_interval_ms: int = 10
    memory_sampling_interval_ms: int = 100

    max_heap: Optional[str] = None
    min_heap: Optional[str] = None
    use_g1gc: bool = True

    heapdump_delay_seconds: int = 5
    mat_path: Optional[Path] = None
    mat_query: str = "suspects"
    mat_format: str = "csv"

    output_dir: Path = Path("analysis") / "tai_e_profiling"


class MultiLayerProfiler:
    """Orchestrates optional profilers around a Tai-e analysis run."""

    def __init__(self, config: ProfilingConfiguration) -> None:
        self.config = config
        self.config.output_dir = self.config.output_dir.expanduser().resolve()
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        self.session_id = int(time.time())

    def profile_tai_e_analysis(
        self,
        source_code: str,
        source_path: Optional[str],
        tai_e_config: Dict[str, Any],
        tai_e_home: Optional[str],
    ) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "session_id": self.session_id,
            "timestamp": time.time(),
            "layers": {},
            "process_metrics": {},
            "elapsed_time": 0.0,
            "return_code": None,
            "errors": [],
        }

        integration = TaiEIntegration(
            TaiEConfig(
                enabled=True,
                tai_e_home=tai_e_home,
                main_class=tai_e_config.get("main_class"),
                cs=tai_e_config.get("cs", "1-obj"),
                timeout=tai_e_config.get("timeout"),
                only_app=bool(tai_e_config.get("only_app", True)),
                allow_phantom=bool(tai_e_config.get("allow_phantom", True)),
                prepend_jvm=bool(tai_e_config.get("prepend_jvm", False)),
                java_version=tai_e_config.get("java_version"),
                classpath=tai_e_config.get("classpath"),
            )
        )

        tai_e_home_path = integration._resolve_tai_e_home()
        jar_path = integration._find_tai_e_jar(tai_e_home_path)
        if not jar_path:
            results["errors"].append("tai_e_jar_not_found")
            return results

        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = Path(tmpdir)
            src_dir = base_dir / "src"
            classes_dir = base_dir / "classes"
            src_dir.mkdir(parents=True, exist_ok=True)
            classes_dir.mkdir(parents=True, exist_ok=True)

            package_name, class_name = integration._extract_package_and_class(
                source_code, source_path
            )
            if not class_name:
                results["errors"].append("class_name_not_found")
                return results

            integration._write_source_file(
                src_dir, package_name, class_name, source_code, source_path
            )
            main_class = tai_e_config.get("main_class")
            synthetic_entrypoint = False
            if not main_class:
                if MAIN_RE.search(source_code):
                    main_class = integration._fqn(package_name, class_name)
                else:
                    main_class = integration._write_entrypoint_wrapper(
                        src_dir, package_name, class_name, source_code
                    )
                    synthetic_entrypoint = True

            compile_errors = integration._compile_sources(src_dir, classes_dir)
            if compile_errors:
                results["errors"].extend(compile_errors)
                return results

            output_dir = (self.config.output_dir / f"tai_e_{self.session_id}").resolve()
            output_dir.mkdir(parents=True, exist_ok=True)

            cmd = self._build_tai_e_command(
                jar_path=jar_path,
                classes_dir=classes_dir,
                main_class=main_class,
                tai_e_config=tai_e_config,
                output_dir=output_dir,
            )

            system_monitor = SystemMonitor() if self.config.enable_system_profiling else None
            if system_monitor:
                system_monitor.start()

            start_time = time.time()
            tai_e_cwd = self._resolve_tai_e_cwd(jar_path)
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(tai_e_cwd),
            )
            monitor_result = self._monitor_process(process, output_dir)
            results["process_metrics"] = monitor_result.get("metrics", {})
            if monitor_result.get("heapdump"):
                heapdump_info = monitor_result.get("heapdump") or {}
                results["layers"]["heapdump"] = heapdump_info
                if heapdump_info.get("path"):
                    results["heapdump_path"] = heapdump_info.get("path")

            stdout, stderr = process.communicate()
            results["elapsed_time"] = time.time() - start_time
            results["return_code"] = process.returncode
            (output_dir / "tai-e.stdout").write_text(stdout or "", encoding="utf-8")
            (output_dir / "tai-e.stderr").write_text(stderr or "", encoding="utf-8")

            heapdump_path = results.get("heapdump_path")
            if heapdump_path:
                mat_info = self._run_mat(Path(heapdump_path), output_dir)
                results["layers"]["mat"] = mat_info
                if mat_info.get("csv_path"):
                    results["mat_csv_path"] = mat_info.get("csv_path")
                if mat_info.get("report_path"):
                    results["mat_report_path"] = mat_info.get("report_path")
                if mat_info.get("object_profile_report"):
                    results["object_profile_report"] = mat_info.get("object_profile_report")

            if system_monitor:
                results["layers"]["system"] = system_monitor.stop()

            if self.config.enable_cpu_profiling or self.config.enable_jfr:
                results["layers"]["cpu"] = self._collect_cpu_profiling_results(output_dir)

            if self.config.enable_memory_profiling:
                results["layers"]["memory"] = self._collect_memory_profiling_results()

            if self.config.enable_tai_e_profiling:
                results["layers"]["tai_e"] = self._collect_tai_e_profiling_results(output_dir)

            results["tai_e_output_dir"] = str(output_dir)
            results["synthetic_entrypoint"] = synthetic_entrypoint
            report_path = self._generate_profiling_report(results)
            results["profiling_report"] = report_path

        return results

    def _build_jvm_options(self) -> List[str]:
        options: List[str] = []
        if self.config.min_heap:
            options.append(f"-Xms{self.config.min_heap}")
        if self.config.max_heap:
            options.append(f"-Xmx{self.config.max_heap}")
        if self.config.use_g1gc:
            options.append("-XX:+UseG1GC")

        if self.config.enable_jfr:
            jfr_file = self.config.output_dir / f"jfr-{self.session_id}.jfr"
            options.extend([
                "-XX:+UnlockDiagnosticVMOptions",
                "-XX:+DebugNonSafepoints",
                f"-XX:StartFlightRecording=filename={jfr_file},settings=profile",
            ])

        if self.config.enable_cpu_profiling and self.config.async_profiler_path:
            profiler_path = self.config.async_profiler_path
            if profiler_path.exists():
                output_file = self.config.output_dir / f"async-profiler-{self.session_id}.jfr"
                options.append(
                    f"-agentpath:{profiler_path}=start,event=cpu,"
                    f"file={output_file},interval={self.config.cpu_sampling_interval_ms}ms"
                )
            else:
                logger.warning("async-profiler not found at %s", profiler_path)

        if self.config.enable_memory_profiling and self.config.yourkit_agent_path:
            agent_path = self.config.yourkit_agent_path
            if agent_path.exists():
                snapshot_dir = self.config.output_dir / "yourkit_snapshots"
                snapshot_dir.mkdir(exist_ok=True)
                options.append(
                    f"-agentpath:{agent_path}=dir={snapshot_dir},sampling,probe_disable=*,onexit=memory"
                )
            else:
                logger.warning("YourKit agent not found at %s", agent_path)

        if self.config.enable_jfr:
            gc_log = self.config.output_dir / f"gc-{self.session_id}.log"
            options.append(f"-Xlog:gc*:file={gc_log}:time,level,tags")

        return options

    def _capture_heap_dump(self, pid: int, output_dir: Path) -> Dict[str, Any]:
        jcmd = shutil.which("jcmd")
        if not jcmd:
            return {"error": "jcmd_not_found"}
        if PSUTIL_AVAILABLE and not psutil.pid_exists(pid):
            return {"error": "process_exited"}
        heapdump_path = (output_dir / f"heapdump_{self.session_id}.hprof").resolve()
        try:
            result = subprocess.run(
                [jcmd, str(pid), "GC.heap_dump", str(heapdump_path)],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return {"error": "heapdump_failed", "stderr": result.stderr.strip()}
            if not heapdump_path.exists():
                return {
                    "error": "heapdump_missing",
                    "stderr": result.stderr.strip(),
                    "stdout": result.stdout.strip(),
                }
        except Exception as exc:
            return {"error": "heapdump_exception", "stderr": str(exc)}
        return {"path": str(heapdump_path)}

    def _run_mat(self, heapdump_path: Path, output_dir: Path) -> Dict[str, Any]:
        mat_cmd = self._resolve_mat_command()
        if not mat_cmd:
            return {"error": "mat_not_found"}
        query = (self.config.mat_query or "").strip()
        query_lower = query.lower()
        report_id: Optional[str] = None
        report_suffix: Optional[str] = None

        if query_lower in {"histogram", "suspects", "leak_suspects", "leak-suspects"}:
            report_id = "org.eclipse.mat.api:suspects"
            report_suffix = "Leak_Suspects"
        elif query_lower in {"top_components", "top-components"}:
            report_id = "org.eclipse.mat.api:top_components"
            report_suffix = "Top_Components"
        elif ":" in query:
            report_id = query
            if query_lower.endswith("suspects"):
                report_suffix = "Leak_Suspects"
            elif query_lower.endswith("top_components"):
                report_suffix = "Top_Components"

        if report_id:
            cmd = mat_cmd + [str(heapdump_path), report_id]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return {
                    "error": "mat_failed",
                    "stderr": result.stderr.strip(),
                    "stdout": result.stdout.strip(),
                }
            report_path: Optional[Path] = None
            if report_suffix:
                candidate = heapdump_path.with_name(f"{heapdump_path.stem}_{report_suffix}.zip")
                if candidate.exists():
                    report_path = candidate
            if not report_path:
                matches = list(heapdump_path.parent.glob(f"{heapdump_path.stem}_*.zip"))
                if matches:
                    report_path = max(matches, key=lambda p: p.stat().st_mtime)
            if report_path:
                return {"report_path": str(report_path)}
            return {}

        csv_path = output_dir / f"mat_{query_lower}_{self.session_id}.csv"
        cmd = mat_cmd + [
            str(heapdump_path),
            f"org.eclipse.mat.api:{query}",
            f"-format={self.config.mat_format}",
            "-output",
            str(csv_path),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0 or not csv_path.exists():
            return {
                "error": "mat_failed",
                "stderr": result.stderr.strip(),
                "stdout": result.stdout.strip(),
            }
        mat_info: Dict[str, Any] = {"csv_path": str(csv_path)}
        try:
            from core.performance.object_profiler import ObjectCentricProfiler

            report_path = output_dir / f"object_profile_mat_{self.session_id}.html"
            profiler = ObjectCentricProfiler(csv_path)
            profiler.generate_optimization_report(report_path)
            mat_info["object_profile_report"] = str(report_path)
        except Exception as exc:
            mat_info["object_profile_error"] = str(exc)
        return mat_info

    def _resolve_mat_command(self) -> Optional[List[str]]:
        mat_path = self.config.mat_path
        if not mat_path:
            env = os.getenv("MAT_HOME") or os.getenv("MAT_PATH")
            if env:
                mat_path = Path(env).expanduser()
        if not mat_path:
            return None
        mat_path = mat_path.expanduser()
        if mat_path.is_dir():
            for name in ("ParseHeapDump.sh", "ParseHeapDump.bat"):
                candidate = mat_path / name
                if candidate.exists():
                    return [str(candidate)]
            return None
        return [str(mat_path)]

    def _build_tai_e_command(
        self,
        jar_path: Path,
        classes_dir: Path,
        main_class: str,
        tai_e_config: Dict[str, Any],
        output_dir: Path,
    ) -> List[str]:
        cmd = ["java"]
        cmd.extend(self._build_jvm_options())
        cmd.extend(["-jar", str(jar_path)])
        cmd.extend(["-cp", str(classes_dir)])
        cmd.extend(["-m", main_class])

        java_version = tai_e_config.get("java_version")
        if java_version:
            cmd.extend(["-java", str(java_version)])
        if tai_e_config.get("prepend_jvm"):
            cmd.append("--prepend-JVM")
        if tai_e_config.get("allow_phantom", True):
            cmd.append("--allow-phantom")
        cmd.extend(["--output-dir", str(output_dir)])

        analysis_opts = [
            f"pta=cs:{tai_e_config.get('cs', '1-obj')}",
            "dump-yaml:true",
            f"only-app:{str(tai_e_config.get('only_app', True)).lower()}",
            f"implicit-entries:{str(tai_e_config.get('implicit_entries', True)).lower()}",
        ]
        timeout = tai_e_config.get("timeout")
        if timeout:
            analysis_opts.append(f"time-limit:{int(timeout)}")
        if tai_e_config.get("taint_config"):
            analysis_opts.append(f"taint-config:{tai_e_config.get('taint_config')}")
        if self.config.enable_tai_e_profiling:
            analysis_opts.append("plugins:profiler")

        cmd.extend(["-a", ";".join(analysis_opts)])
        logger.info("Tai-e profiling command: %s", " ".join(cmd))
        return cmd

    def _resolve_tai_e_cwd(self, jar_path: Path) -> Path:
        candidates: List[Path] = [jar_path.parent, jar_path.parent.parent]
        for base in list(candidates):
            candidates.extend([
                base / "source" / "Tai-e",
                base / "source" / "tai-e",
                base / "Tai-e",
                base / "tai-e",
            ])
        for root in candidates:
            if (root / "java-benchmarks").exists():
                return root
        return jar_path.parent

    def _monitor_process(self, process: subprocess.Popen, output_dir: Path) -> Dict[str, Any]:
        if not PSUTIL_AVAILABLE:
            heapdump_info: Dict[str, Any] = {}
            if self.config.enable_heapdump:
                time.sleep(self.config.heapdump_delay_seconds)
                if process.poll() is None:
                    heapdump_info = self._capture_heap_dump(process.pid, output_dir)
            return {"metrics": {"psutil_available": False}, "heapdump": heapdump_info or None}

        metrics = {
            "cpu_samples": [],
            "rss_samples": [],
            "thread_samples": [],
        }
        heapdump_info: Dict[str, Any] = {}
        heapdump_done = False
        heapdump_start = time.time()
        if self.config.enable_heapdump and self.config.heapdump_delay_seconds <= 0:
            heapdump_info = self._capture_heap_dump(process.pid, output_dir)
            heapdump_done = True
        try:
            ps_process = psutil.Process(process.pid)
            while process.poll() is None:
                metrics["cpu_samples"].append(ps_process.cpu_percent(interval=0.3))
                mem_info = ps_process.memory_info()
                metrics["rss_samples"].append(mem_info.rss / 1024 / 1024)
                metrics["thread_samples"].append(ps_process.num_threads())
                if self.config.enable_heapdump and not heapdump_done:
                    elapsed = time.time() - heapdump_start
                    if elapsed >= self.config.heapdump_delay_seconds:
                        heapdump_info = self._capture_heap_dump(process.pid, output_dir)
                        heapdump_done = True
            if self.config.enable_heapdump and not heapdump_done:
                heapdump_info = {"error": "process_exited_before_heapdump"}
        except psutil.ZombieProcess:
            logger.debug("Process monitoring ended: PID is zombie (%s)", process.pid)
            if self.config.enable_heapdump and not heapdump_done:
                heapdump_info = {"error": "process_zombie_before_heapdump"}
        except psutil.NoSuchProcess:
            logger.debug("Process monitoring ended: process exited (%s)", process.pid)
            if self.config.enable_heapdump and not heapdump_done:
                heapdump_info = {"error": "process_exited_before_heapdump"}
        except Exception as exc:
            logger.warning("Process monitoring failed: %s", exc)

        def _summarize(values: List[float]) -> Dict[str, float]:
            if not values:
                return {"mean": 0.0, "max": 0.0}
            return {"mean": sum(values) / len(values), "max": max(values)}

        return {
            "metrics": {
                "psutil_available": True,
                "cpu_percent": _summarize(metrics["cpu_samples"]),
                "memory_rss_mb": _summarize(metrics["rss_samples"]),
                "num_threads": _summarize(metrics["thread_samples"]),
            },
            "heapdump": heapdump_info or None,
        }

    def _collect_cpu_profiling_results(self, output_dir: Path) -> Dict[str, Any]:
        jfr_files = list(self.config.output_dir.glob(f"jfr-{self.session_id}.jfr"))
        jfr_path = str(jfr_files[0]) if jfr_files else None
        flamegraph = None
        if jfr_files and shutil.which("jfr2flame"):
            flamegraph = self._generate_flamegraph(Path(jfr_path))
        return {
            "jfr_file": jfr_path,
            "flamegraph": str(flamegraph) if flamegraph else None,
        }

    def _generate_flamegraph(self, jfr_file: Path) -> Optional[Path]:
        output_svg = self.config.output_dir / f"flamegraph-{self.session_id}.svg"
        try:
            subprocess.run(
                ["jfr2flame", str(jfr_file), str(output_svg)],
                check=True,
                capture_output=True,
                text=True,
            )
            return output_svg
        except Exception as exc:
            logger.warning("Failed to generate flamegraph: %s", exc)
            return None

    def _collect_memory_profiling_results(self) -> Dict[str, Any]:
        snapshot_dir = self.config.output_dir / "yourkit_snapshots"
        snapshots = list(snapshot_dir.glob("*.snapshot"))
        if not snapshots:
            return {"error": "no_snapshots_found"}
        latest = max(snapshots, key=lambda p: p.stat().st_mtime)
        return {
            "snapshot_file": str(latest),
            "snapshot_size_mb": latest.stat().st_size / 1024 / 1024,
        }

    def _collect_tai_e_profiling_results(self, output_dir: Path) -> Dict[str, Any]:
        profiler_file = output_dir / "pta-profiler.txt"
        if not profiler_file.exists():
            return {"error": "pta_profiler_not_found"}
        content = profiler_file.read_text(encoding="utf-8", errors="ignore")
        hotspots = []
        for line in content.splitlines():
            match = re.match(r'\d+\.\s+(.+?)\s+-\s+([\d.]+)s\s+\(([\d.]+)%\)', line)
            if match:
                hotspots.append({
                    "method": match.group(1),
                    "time_seconds": float(match.group(2)),
                    "percentage": float(match.group(3)),
                })
        return {"hotspot_methods": hotspots, "profiler_file": str(profiler_file)}

    def _generate_profiling_report(self, results: Dict[str, Any]) -> str:
        report_path = self.config.output_dir / f"profiling_report_{self.session_id}.html"
        report_path.write_text(self._build_report_html(results), encoding="utf-8")
        return str(report_path)

    def _build_report_html(self, results: Dict[str, Any]) -> str:
        cpu = results.get("layers", {}).get("cpu", {})
        heapdump_path = results.get("heapdump_path")
        mat_csv_path = results.get("mat_csv_path")
        mat_report_path = results.get("mat_report_path")
        object_profile_report = results.get("object_profile_report")
        return f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Tai-e Profiling Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 20px; }}
    .summary {{ background: #f0f0f0; padding: 16px; border-radius: 6px; }}
    .metric {{ display: inline-block; margin: 8px; padding: 10px; background: #e8f5e9; border-radius: 4px; }}
    .layer {{ margin-top: 20px; padding: 12px; border: 1px solid #ddd; border-radius: 6px; }}
  </style>
</head>
<body>
  <h1>Tai-e Profiling Report</h1>
  <p><strong>Session:</strong> {results.get("session_id")}</p>
  <div class="summary">
    <div class="metric"><strong>Total Time:</strong> {results.get("elapsed_time", 0.0):.2f}s</div>
    <div class="metric"><strong>Return Code:</strong> {results.get("return_code")}</div>
  </div>
  <div class="layer">
    <h2>Heap Dump / MAT</h2>
    <p><strong>Heap dump:</strong> {heapdump_path or "not captured"}</p>
    <p><strong>MAT report:</strong> {mat_report_path or "not generated"}</p>
    <p><strong>MAT CSV:</strong> {mat_csv_path or "not generated"}</p>
    <p><strong>Object profile:</strong> {object_profile_report or "not generated"}</p>
  </div>
  <div class="layer">
    <h2>CPU Profiling</h2>
    <p><strong>JFR:</strong> {cpu.get("jfr_file") or "not collected"}</p>
    <p><strong>Flamegraph:</strong> {cpu.get("flamegraph") or "not generated"}</p>
  </div>
</body>
</html>
"""


class SystemMonitor:
    def __init__(self) -> None:
        self.start_time = None
        self.samples: List[float] = []

    def start(self) -> None:
        self.start_time = time.time()

    def stop(self) -> Dict[str, Any]:
        return {
            "duration": time.time() - self.start_time if self.start_time else 0.0,
            "samples_collected": len(self.samples),
        }
