"""Java source instrumentation for runtime value logging."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import re

PACKAGE_RE = re.compile(r'^\s*package\s+([\w.]+)\s*;', re.MULTILINE)
ASSIGN_RE = re.compile(
    r'^\s*(?:final\s+)?(?:[\w<>\[\],\s]+)\s+(\w+)\s*='
)
CONTROL_PREFIXES = ("if", "for", "while", "switch", "catch", "return", "throw")


@dataclass
class InstrumentationResult:
    package_name: Optional[str]
    instrumented_file: Path
    logger_file: Path


class JavaValueInstrumenter:
    """Instruments Java source code to log concrete runtime values."""

    def __init__(self, logger_class: str = "ValueLogger") -> None:
        self.logger_class = logger_class

    def instrument(self, source_path: Path, output_dir: Path) -> InstrumentationResult:
        source = source_path.read_text(encoding="utf-8", errors="ignore")
        package_name = self._extract_package(source)

        logger_file = self._write_logger_java(output_dir, package_name)
        instrumented_file = output_dir / source_path.name
        instrumented_file.write_text(
            self._instrument_source(source),
            encoding="utf-8",
        )

        return InstrumentationResult(
            package_name=package_name,
            instrumented_file=instrumented_file,
            logger_file=logger_file,
        )

    def _extract_package(self, source: str) -> Optional[str]:
        match = PACKAGE_RE.search(source)
        return match.group(1) if match else None

    def _instrument_source(self, source: str) -> str:
        lines = source.splitlines()
        instrumented = []
        in_block_comment = False
        for line in lines:
            stripped = line.strip()
            instrumented.append(line)

            if "/*" in stripped and "*/" not in stripped:
                in_block_comment = True
            if in_block_comment:
                if "*/" in stripped:
                    in_block_comment = False
                continue

            if not stripped or stripped.startswith("//"):
                continue
            if stripped.startswith(CONTROL_PREFIXES):
                continue
            if "==" in line or ">=" in line or "<=" in line or "!=" in line:
                continue
            if ";" not in line:
                continue
            match = ASSIGN_RE.match(line)
            if not match:
                continue

            var_name = match.group(1)
            indent = " " * (len(line) - len(line.lstrip()))
            instrumented.append(f'{indent}{self.logger_class}.log("{var_name}", {var_name});')

        return "\n".join(instrumented) + "\n"

    def _write_logger_java(self, output_dir: Path, package_name: Optional[str]) -> Path:
        logger_path = output_dir / f"{self.logger_class}.java"
        package_line = f"package {package_name};\n\n" if package_name else ""
        logger_path.write_text(
            f"""{package_line}import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class {self.logger_class} {{
    private static final String LOG_FILE = "value_log.json";
    private static final List<String> logs = new ArrayList<>();

    static {{
        Runtime.getRuntime().addShutdownHook(new Thread({self.logger_class}::flushLogs));
    }}

    public static void log(String varName, Object value) {{
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        StackTraceElement caller = stack.length > 3 ? stack[3] : stack[stack.length - 1];
        String location = caller.getClassName() + "." + caller.getMethodName() + ":" + caller.getLineNumber();
        String safeValue = value == null ? "null" : value.toString().replace("\\\"", "'");
        long ts = System.currentTimeMillis();
        String entry = "{{\\"var\\": \\"" + varName + "\\", \\"value\\": \\"" + safeValue + "\\", \\"location\\": \\"" + location + "\\", \\"timestamp\\": " + ts + "}}";
        synchronized (logs) {{
            logs.add(entry);
        }}
    }}

    private static void flushLogs() {{
        try (PrintWriter writer = new PrintWriter(new FileWriter(LOG_FILE))) {{
            writer.println("{{");
            writer.println("  \\"value_logs\\": [");
            for (int i = 0; i < logs.size(); i++) {{
                writer.print("    " + logs.get(i));
                if (i < logs.size() - 1) {{
                    writer.println(",");
                }} else {{
                    writer.println();
                }}
            }}
            writer.println("  ]");
            writer.println("}}");
        }} catch (IOException e) {{
            e.printStackTrace();
        }}
    }}
}}
""",
            encoding="utf-8",
        )
        return logger_path
