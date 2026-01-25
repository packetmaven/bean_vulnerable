package com.beanvulnerable.aeg;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Experimental AEG-Lite analyzer for Java bytecode.
 *
 * This stage uses ASM to extract bytecode-level metrics to seed future
 * symbolic-execution integration (JPF/Z3). It does not execute JPF yet.
 */
public class AegLiteAnalyzer {
    public static void main(String[] args) throws Exception {
        Map<String, String> options = parseArgs(args);
        String classPath = options.get("class");
        String classesDir = options.get("classes-dir");
        String output = options.get("out");

        if (classPath == null && classesDir == null) {
            System.err.println("Usage: --class <file.class> | --classes-dir <dir> [--out <file.json>]");
            System.exit(2);
        }

        List<Path> classFiles = new ArrayList<>();
        if (classPath != null) {
            classFiles.add(Paths.get(classPath));
        }
        if (classesDir != null) {
            Path root = Paths.get(classesDir);
            if (Files.exists(root)) {
                Files.walk(root)
                    .filter(p -> p.toString().endsWith(".class"))
                    .forEach(classFiles::add);
            }
        }

        List<ClassReport> reports = new ArrayList<>();
        for (Path classFile : classFiles) {
            try {
                reports.add(analyzeClass(classFile));
            } catch (IOException exc) {
                System.err.println("Failed to analyze " + classFile + ": " + exc.getMessage());
            }
        }

        Report report = new Report(reports);
        String json = report.toJson();

        if (output != null) {
            Files.write(Paths.get(output), json.getBytes("UTF-8"));
        } else {
            System.out.println(json);
        }
    }

    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> options = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("--class".equals(arg) && i + 1 < args.length) {
                options.put("class", args[++i]);
            } else if ("--classes-dir".equals(arg) && i + 1 < args.length) {
                options.put("classes-dir", args[++i]);
            } else if ("--out".equals(arg) && i + 1 < args.length) {
                options.put("out", args[++i]);
            }
        }
        return options;
    }

    private static ClassReport analyzeClass(Path classFile) throws IOException {
        try (InputStream input = Files.newInputStream(classFile)) {
            ClassReader reader = new ClassReader(input);
            ClassNode node = new ClassNode();
            reader.accept(node, ClassReader.SKIP_DEBUG);

            ClassReport report = new ClassReport(node.name.replace('/', '.'));
            for (Object methodObj : node.methods) {
                MethodNode method = (MethodNode) methodObj;
                MethodReport methodReport = analyzeMethod(method);
                report.methods.add(methodReport);
                report.methodCount += 1;
                report.instructionCount += methodReport.instructionCount;
                report.invocationCount += methodReport.invocationCount;
            }
            return report;
        }
    }

    private static MethodReport analyzeMethod(MethodNode method) {
        MethodReport report = new MethodReport(method.name, method.desc);
        if (method.instructions == null) {
            return report;
        }

        for (AbstractInsnNode insn = method.instructions.getFirst();
             insn != null;
             insn = insn.getNext()) {
            int opcode = insn.getOpcode();
            if (opcode < 0) {
                continue;
            }
            report.instructionCount += 1;
            if (opcode >= Opcodes.INVOKEVIRTUAL && opcode <= Opcodes.INVOKEDYNAMIC) {
                report.invocationCount += 1;
                if (insn instanceof MethodInsnNode) {
                    MethodInsnNode call = (MethodInsnNode) insn;
                    report.calls.add(call.owner.replace('/', '.') + "." + call.name + call.desc);
                }
            }
            if (opcode >= Opcodes.IFEQ && opcode <= Opcodes.IF_ACMPNE) {
                report.branchCount += 1;
            }
        }

        return report;
    }

    private static String escape(String input) {
        if (input == null) {
            return "";
        }
        return input.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r");
    }

    private static class Report {
        List<ClassReport> classes;
        int classCount = 0;
        int methodCount = 0;
        int instructionCount = 0;
        int invocationCount = 0;

        Report(List<ClassReport> classes) {
            this.classes = classes;
            for (ClassReport report : classes) {
                classCount += 1;
                methodCount += report.methodCount;
                instructionCount += report.instructionCount;
                invocationCount += report.invocationCount;
            }
        }

        String toJson() {
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            sb.append("\"classes\":").append("[");
            for (int i = 0; i < classes.size(); i++) {
                if (i > 0) {
                    sb.append(",");
                }
                sb.append(classes.get(i).toJson());
            }
            sb.append("],");
            sb.append("\"totals\":{");
            sb.append("\"class_count\":").append(classCount).append(",");
            sb.append("\"method_count\":").append(methodCount).append(",");
            sb.append("\"instruction_count\":").append(instructionCount).append(",");
            sb.append("\"invocation_count\":").append(invocationCount);
            sb.append("}");
            sb.append("}");
            return sb.toString();
        }
    }

    private static class ClassReport {
        String name;
        int methodCount = 0;
        int instructionCount = 0;
        int invocationCount = 0;
        List<MethodReport> methods = new ArrayList<>();

        ClassReport(String name) {
            this.name = name;
        }

        String toJson() {
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            sb.append("\"name\":\"").append(escape(name)).append("\",");
            sb.append("\"method_count\":").append(methodCount).append(",");
            sb.append("\"instruction_count\":").append(instructionCount).append(",");
            sb.append("\"invocation_count\":").append(invocationCount).append(",");
            sb.append("\"methods\":[");
            for (int i = 0; i < methods.size(); i++) {
                if (i > 0) {
                    sb.append(",");
                }
                sb.append(methods.get(i).toJson());
            }
            sb.append("]}");
            return sb.toString();
        }
    }

    private static class MethodReport {
        String name;
        String descriptor;
        int instructionCount = 0;
        int invocationCount = 0;
        int branchCount = 0;
        List<String> calls = new ArrayList<>();

        MethodReport(String name, String descriptor) {
            this.name = name;
            this.descriptor = descriptor;
        }

        String toJson() {
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            sb.append("\"name\":\"").append(escape(name)).append("\",");
            sb.append("\"descriptor\":\"").append(escape(descriptor)).append("\",");
            sb.append("\"instruction_count\":").append(instructionCount).append(",");
            sb.append("\"invocation_count\":").append(invocationCount).append(",");
            sb.append("\"branch_count\":").append(branchCount).append(",");
            sb.append("\"calls\":[");
            for (int i = 0; i < calls.size(); i++) {
                if (i > 0) {
                    sb.append(",");
                }
                sb.append("\"").append(escape(calls.get(i))).append("\"");
            }
            sb.append("]}");
            return sb.toString();
        }
    }
}
