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

    async_profiler_path: Optional[Path] = None
    yourkit_agent_path: Optional[Path] = None

    cpu_sampling_interval_ms: int = 10
    memory_sampling_interval_ms: int = 100

    max_heap: Optional[str] = None
    min_heap: Optional[str] = None
    use_g1gc: bool = True

    output_dir: Path = Path("analysis") / "tai_e_profiling"


class MultiLayerProfiler:
    """Orchestrates optional profilers around a Tai-e analysis run."""

    def __init__(self, config: ProfilingConfiguration) -> None:
        self.config = config
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

            output_dir = self.config.output_dir / f"tai_e_{self.session_id}"
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
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            results["process_metrics"] = self._monitor_process(process)
            stdout, stderr = process.communicate()
            results["elapsed_time"] = time.time() - start_time
            results["return_code"] = process.returncode
            (output_dir / "tai-e.stdout").write_text(stdout or "", encoding="utf-8")
            (output_dir / "tai-e.stderr").write_text(stderr or "", encoding="utf-8")

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

    def _monitor_process(self, process: subprocess.Popen) -> Dict[str, Any]:
        if not PSUTIL_AVAILABLE:
            return {"psutil_available": False}

        metrics = {
            "cpu_samples": [],
            "rss_samples": [],
            "thread_samples": [],
        }
        try:
            ps_process = psutil.Process(process.pid)
            while process.poll() is None:
                metrics["cpu_samples"].append(ps_process.cpu_percent(interval=0.3))
                mem_info = ps_process.memory_info()
                metrics["rss_samples"].append(mem_info.rss / 1024 / 1024)
                metrics["thread_samples"].append(ps_process.num_threads())
        except Exception as exc:
            logger.warning("Process monitoring failed: %s", exc)

        def _summarize(values: List[float]) -> Dict[str, float]:
            if not values:
                return {"mean": 0.0, "max": 0.0}
            return {"mean": sum(values) / len(values), "max": max(values)}

        return {
            "psutil_available": True,
            "cpu_percent": _summarize(metrics["cpu_samples"]),
            "memory_rss_mb": _summarize(metrics["rss_samples"]),
            "num_threads": _summarize(metrics["thread_samples"]),
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
