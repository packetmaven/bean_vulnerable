"""AEG-Lite Java analyzer bridge (experimental)."""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional

LOG = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
JAVA_AEG_DIR = REPO_ROOT / "java" / "aeg-lite"
JAVA_POM = JAVA_AEG_DIR / "pom.xml"
JAVA_SRC_DIR = JAVA_AEG_DIR / "src" / "main" / "java"
SHADED_JAR = JAVA_AEG_DIR / "target" / "aeg-lite-java-0.1.0-all.jar"


def _build_java_env(java_home: Optional[str] = None) -> Dict[str, str]:
    env = dict(os.environ)
    if java_home:
        env["JAVA_HOME"] = java_home
        env["PATH"] = f"{java_home}/bin:{env.get('PATH', '')}"
    java_opts = env.get("JAVA_TOOL_OPTIONS", "")
    if "-Dfile.encoding=UTF-8" not in java_opts:
        env["JAVA_TOOL_OPTIONS"] = (java_opts + " " if java_opts else "") + "-Dfile.encoding=UTF-8"
    env.setdefault("LC_ALL", "en_US.UTF-8")
    env.setdefault("LANG", "en_US.UTF-8")
    return env


def _find_executable(name: str, java_home: Optional[str] = None) -> Optional[str]:
    if java_home:
        candidate = Path(java_home) / "bin" / name
        if candidate.exists():
            return str(candidate)
    return shutil.which(name)


def _jar_is_stale() -> bool:
    if not SHADED_JAR.exists():
        return True
    jar_mtime = SHADED_JAR.stat().st_mtime
    pom_mtime = JAVA_POM.stat().st_mtime if JAVA_POM.exists() else 0
    if pom_mtime > jar_mtime:
        return True
    if JAVA_SRC_DIR.exists():
        for source in JAVA_SRC_DIR.rglob("*.java"):
            if source.stat().st_mtime > jar_mtime:
                return True
    return False


def _ensure_jar(java_home: Optional[str] = None) -> Optional[str]:
    if SHADED_JAR.exists() and not _jar_is_stale():
        return str(SHADED_JAR)
    mvn = _find_executable("mvn")
    if not mvn:
        return None
    env = _build_java_env(java_home)
    cmd = [mvn, "-q", "-f", str(JAVA_POM), "-DskipTests", "package"]
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if result.returncode != 0 or not SHADED_JAR.exists():
        LOG.error("AEG-Lite Java build failed: %s", result.stderr.strip() or result.stdout.strip())
        return None
    return str(SHADED_JAR)


def run_aeg_lite_java(
    source_path: Path,
    java_home: Optional[str] = None,
    generate_pocs: bool = False,
    generate_patches: bool = False,
    use_joern: bool = False,
    enhanced_scan: bool = False,
    enhanced_patches: bool = False,
) -> Dict[str, Any]:
    if not JAVA_POM.exists():
        return {
            "success": False,
            "error": "AEG-Lite Java module missing. See java/aeg-lite.",
            "analysis_method": "asm_bytecode",
        }

    jar_path = _ensure_jar(java_home)
    if not jar_path:
        return {
            "success": False,
            "error": "Maven build failed or mvn not found. Run: mvn -q -f java/aeg-lite/pom.xml -DskipTests package",
            "analysis_method": "asm_bytecode",
        }

    java_bin = _find_executable("java", java_home)
    if not java_bin:
        return {
            "success": False,
            "error": "java not found on PATH. Set JAVA_HOME to a JDK.",
            "analysis_method": "asm_bytecode",
        }

    env = _build_java_env(java_home)
    analyze_cmd = [
        java_bin,
        "-cp",
        jar_path,
        "com.beanvulnerable.aeg.AegLiteRunner",
        "--source",
        str(source_path),
    ]
    if generate_pocs:
        analyze_cmd.append("--generate-pocs")
    if generate_patches:
        analyze_cmd.append("--generate-patches")
    if use_joern:
        analyze_cmd.append("--use-joern")
    if enhanced_scan:
        analyze_cmd.append("--enhanced-scan")
    if enhanced_patches:
        analyze_cmd.append("--enhanced-patches")

    extra_classpath = env.get("AEG_LITE_CLASSPATH")
    if extra_classpath:
        analyze_cmd.extend(["--classpath", extra_classpath])

    analyze = subprocess.run(
        analyze_cmd,
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
    )
    if analyze.returncode != 0:
        return {
            "success": False,
            "error": analyze.stderr.strip() or analyze.stdout.strip(),
            "analysis_method": "asm_bytecode",
        }

    try:
        payload = json.loads(analyze.stdout)
    except Exception as exc:
        return {
            "success": False,
            "error": f"Failed to parse analyzer output: {exc}",
            "analysis_method": "asm_bytecode",
        }

    return {
        "success": True,
        "analysis_method": "asm_bytecode",
        "report": payload,
    }
