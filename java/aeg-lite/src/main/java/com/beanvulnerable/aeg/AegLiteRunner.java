package com.beanvulnerable.aeg;

import com.beanvulnerable.aeg.domain.ClassAnalysis;
import com.beanvulnerable.aeg.domain.Vulnerability;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;

import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.Trees;

/**
 * AEG-Lite Runner: orchestrates bytecode analysis and optional PoC/Patch synthesis.
 */
public class AegLiteRunner {

    public static void main(String[] args) throws Exception {
        Map<String, String> options = parseArgs(args);
        String classPath = options.get("class");
        String classesDir = options.get("classes-dir");
        String sourcePath = options.get("source");
        String extraClasspath = options.get("classpath");
        boolean generatePocs = options.containsKey("generate-pocs");
        boolean generatePatches = options.containsKey("generate-patches");
        boolean useJoern = options.containsKey("use-joern");
        boolean enhancedScan = options.containsKey("enhanced-scan");
        boolean enhancedPatches = options.containsKey("enhanced-patches");
        if (enhancedPatches) {
            enhancedScan = true;
        }

        if ((classPath == null && classesDir == null) && sourcePath != null) {
            classesDir = compileSource(Paths.get(sourcePath), extraClasspath);
        }
        if (classPath == null && classesDir == null) {
            System.err.println("Usage: --class <file.class> | --classes-dir <dir> | --source <file.java> [--classpath <path>]");
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

        BytecodeAnalyzer analyzer = new BytecodeAnalyzer();
        HeuristicVulnerabilityDetector heuristicDetector = new HeuristicVulnerabilityDetector();

        List<Vulnerability> vulnerabilities = new ArrayList<>();
        int analyzedClasses = 0;

        for (Path classFile : classFiles) {
            try {
                ClassAnalysis classAnalysis = analyzer.analyzeClass(classFile.toString());
                analyzedClasses += 1;

                List<Vulnerability> classVulns = trySymbolicAnalysis(classAnalysis);
                if (classVulns.isEmpty()) {
                    classVulns = heuristicDetector.detect(classAnalysis);
                }
                vulnerabilities.addAll(classVulns);
            } catch (IOException exc) {
                System.err.println("Failed to analyze " + classFile + ": " + exc.getMessage());
            }
        }

        List<GeneratedPoC> pocs = new ArrayList<>();
        List<SecurityPatch> patches = new ArrayList<>();
        String pocError = null;
        String patchError = null;

        if (generatePocs) {
            try {
                pocs = tryGeneratePoCs(vulnerabilities);
            } catch (Exception exc) {
                pocError = exc.getMessage();
            }
        }

        if (generatePatches) {
            try {
                Map<String, String> vulnerableCodeMap = buildVulnerableCodeMap(vulnerabilities, sourcePath);
                patches = tryGeneratePatches(vulnerabilities, vulnerableCodeMap);
            } catch (Exception exc) {
                patchError = exc.getMessage();
            }
        }

        Map<String, Object> joernReport = null;
        if (useJoern && sourcePath != null) {
            joernReport = tryRunJoern(Paths.get(sourcePath));
        }

        Map<String, Object> enhancedReport = null;
        if (enhancedScan || enhancedPatches) {
            enhancedReport = runEnhancedPipeline(sourcePath, enhancedPatches);
        }

        String json = buildJsonReport(analyzedClasses, vulnerabilities, pocs, patches, pocError, patchError,
            joernReport, enhancedReport);
        System.out.println(json);
    }

    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> options = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("--class".equals(arg) && i + 1 < args.length) {
                options.put("class", args[++i]);
            } else if ("--classes-dir".equals(arg) && i + 1 < args.length) {
                options.put("classes-dir", args[++i]);
            } else if ("--source".equals(arg) && i + 1 < args.length) {
                options.put("source", args[++i]);
            } else if ("--classpath".equals(arg) && i + 1 < args.length) {
                options.put("classpath", args[++i]);
            } else if ("--generate-pocs".equals(arg)) {
                options.put("generate-pocs", "true");
            } else if ("--generate-patches".equals(arg)) {
                options.put("generate-patches", "true");
            } else if ("--use-joern".equals(arg)) {
                options.put("use-joern", "true");
            } else if ("--enhanced-scan".equals(arg)) {
                options.put("enhanced-scan", "true");
            } else if ("--enhanced-patches".equals(arg)) {
                options.put("enhanced-patches", "true");
            }
        }
        return options;
    }

    private static String compileSource(Path sourceFile, String extraClasspath) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException("JDK required: JavaCompiler not available");
        }
        if (sourceFile == null || !Files.exists(sourceFile)) {
            throw new IllegalArgumentException("Source file not found: " + sourceFile);
        }
        Path outDir = Files.createTempDirectory("aeg_lite_classes_");
        outDir.toFile().deleteOnExit();

        List<String> options = new ArrayList<>();
        options.add("-encoding");
        options.add("UTF-8");
        options.add("-g");
        options.add("-d");
        options.add(outDir.toString());

        String classpath = buildCompileClasspath(extraClasspath);
        if (classpath != null && !classpath.isEmpty()) {
            options.add("-classpath");
            options.add(classpath);
        }

        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        StandardJavaFileManager fileManager = compiler.getStandardFileManager(diagnostics, null, StandardCharsets.UTF_8);
        Iterable<? extends JavaFileObject> compilationUnits = fileManager.getJavaFileObjects(sourceFile.toFile());
        JavaCompiler.CompilationTask task = compiler.getTask(
            null, fileManager, diagnostics, options, null, compilationUnits
        );
        boolean success = Boolean.TRUE.equals(task.call());
        fileManager.close();

        if (!success) {
            String errors = diagnostics.getDiagnostics().stream()
                .filter(d -> d.getKind() == Diagnostic.Kind.ERROR)
                .map(AegLiteRunner::formatDiagnostic)
                .collect(Collectors.joining("\n"));
            throw new IllegalStateException("Compilation failed:\n" + errors);
        }
        return outDir.toString();
    }

    private static String buildCompileClasspath(String extraClasspath) {
        String base = System.getProperty("java.class.path", "");
        if (extraClasspath == null || extraClasspath.trim().isEmpty()) {
            return base;
        }
        if (base == null || base.trim().isEmpty()) {
            return extraClasspath;
        }
        return base + System.getProperty("path.separator") + extraClasspath;
    }

    private static String formatDiagnostic(Diagnostic<? extends JavaFileObject> diagnostic) {
        String source = diagnostic.getSource() != null ? diagnostic.getSource().getName() : "unknown";
        return source + ":" + diagnostic.getLineNumber() + ": " + diagnostic.getMessage(null);
    }

    @SuppressWarnings("unchecked")
    private static List<Vulnerability> trySymbolicAnalysis(ClassAnalysis analysis) {
        try {
            Class<?> executorClass = Class.forName("com.beanvulnerable.aeg.SymbolicExecutor");
            Object executor = executorClass.getConstructor().newInstance();
            Object result = executorClass.getMethod("analyzeClass", ClassAnalysis.class).invoke(executor, analysis);
            return (List<Vulnerability>) result.getClass().getMethod("getVulnerabilities").invoke(result);
        } catch (Exception exc) {
            return new ArrayList<>();
        }
    }

    private static List<GeneratedPoC> tryGeneratePoCs(List<Vulnerability> vulnerabilities) throws Exception {
        PoCSynthesizer synthesizer = new PoCSynthesizer();
        return synthesizer.generatePoCsForVulnerabilities(vulnerabilities);
    }

    private static List<SecurityPatch> tryGeneratePatches(List<Vulnerability> vulnerabilities,
                                                          Map<String, String> vulnerableCodeMap) throws Exception {
        PatchSynthesizer synthesizer = new PatchSynthesizer();
        return synthesizer.generatePatches(vulnerabilities, vulnerableCodeMap);
    }

    private static Map<String, String> buildVulnerableCodeMap(List<Vulnerability> vulnerabilities,
                                                              String sourcePath) {
        Map<String, String> codeMap = new HashMap<>();
        if (sourcePath == null || sourcePath.isEmpty()) {
            return codeMap;
        }
        Path sourceFile = Paths.get(sourcePath);
        if (!Files.exists(sourceFile)) {
            return codeMap;
        }
        try {
            String source = new String(Files.readAllBytes(sourceFile), StandardCharsets.UTF_8);
            for (Vulnerability vulnerability : vulnerabilities) {
                codeMap.put(vulnerability.getId(), source);
            }
        } catch (IOException ignored) {
        }
        return codeMap;
    }

    private static Map<String, Object> tryRunJoern(Path sourceFile) {
        Map<String, Object> report = new HashMap<>();
        String joernBin = System.getenv("JOERN_BIN");
        if (joernBin == null || joernBin.isEmpty()) {
            String joernHome = System.getenv("JOERN_HOME");
            if (joernHome != null && !joernHome.isEmpty()) {
                joernBin = Paths.get(joernHome, "joern").toString();
            }
        }

        if (joernBin == null || joernBin.isEmpty()) {
            report.put("available", false);
            report.put("error", "JOERN_BIN/JOERN_HOME not set");
            return report;
        }

        Path scriptPath = Paths.get(System.getProperty("user.dir"), "comprehensive_graphs.sc");
        if (!Files.exists(scriptPath)) {
            report.put("available", false);
            report.put("error", "comprehensive_graphs.sc not found");
            return report;
        }

        try {
            Path outputDir = Files.createTempDirectory("aeg_joern_");
            ProcessBuilder pb = new ProcessBuilder(joernBin, "--script", scriptPath.toString());
            Map<String, String> env = pb.environment();
            env.put("SOURCE_FILE", sourceFile.toAbsolutePath().toString());
            env.put("OUTPUT_DIR", outputDir.toAbsolutePath().toString());
            Process process = pb.start();
            boolean completed = process.waitFor(120, TimeUnit.SECONDS);
            if (!completed) {
                process.destroy();
                report.put("available", true);
                report.put("error", "joern timeout");
                return report;
            }

            long dotCount = Files.list(outputDir)
                .filter(p -> p.toString().endsWith(".dot"))
                .count();
            report.put("available", true);
            report.put("dot_count", dotCount);
            return report;
        } catch (Exception exc) {
            report.put("available", true);
            report.put("error", exc.getMessage());
            return report;
        }
    }

    private static String buildJsonReport(int analyzedClasses,
                                          List<Vulnerability> vulnerabilities,
                                          List<GeneratedPoC> pocs,
                                          List<SecurityPatch> patches,
                                          String pocError,
                                          String patchError,
                                          Map<String, Object> joernReport,
                                          Map<String, Object> enhancedReport) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"classes_analyzed\":").append(analyzedClasses).append(",");
        sb.append("\"vulnerability_count\":").append(vulnerabilities.size()).append(",");
        sb.append("\"vulnerabilities\":[");
        for (int i = 0; i < vulnerabilities.size(); i++) {
            Vulnerability vuln = vulnerabilities.get(i);
            if (i > 0) {
                sb.append(",");
            }
            sb.append("{");
            String rawId = vuln.getId();
            String normalizedId = normalizeId(rawId);
            sb.append("\"id\":\"").append(escape(normalizedId)).append("\",");
            sb.append("\"raw_id\":\"").append(escape(rawId)).append("\",");
            sb.append("\"type\":\"").append(escape(vuln.getVulnerabilityType())).append("\",");
            sb.append("\"sink_type\":\"").append(escape(vuln.getSinkType())).append("\",");
            sb.append("\"description\":\"").append(escape(vuln.getDescription())).append("\"");
            sb.append("}");
        }
        sb.append("],");
        int pocCount = pocs == null ? 0 : pocs.size();
        int patchCount = patches == null ? 0 : patches.size();
        sb.append("\"poc_count\":").append(pocCount).append(",");
        sb.append("\"patch_count\":").append(patchCount);
        if (pocs != null) {
            sb.append(",\"pocs\":[");
            for (int i = 0; i < pocs.size(); i++) {
                GeneratedPoC poc = pocs.get(i);
                if (i > 0) {
                    sb.append(",");
                }
                sb.append("{");
                sb.append("\"id\":\"").append(escape(poc.getPocId())).append("\",");
                String rawVulnId = poc.getVulnerability().getId();
                sb.append("\"vulnerability_id\":\"")
                    .append(escape(normalizeId(rawVulnId))).append("\",");
                sb.append("\"raw_vulnerability_id\":\"")
                    .append(escape(rawVulnId)).append("\",");
                sb.append("\"type\":\"").append(escape(poc.getVulnerabilityType())).append("\",");
                sb.append("\"status\":\"").append(escape(String.valueOf(poc.getVerificationStatus()))).append("\",");
                sb.append("\"layer1\":").append(poc.isLayer1Verified()).append(",");
                sb.append("\"layer2\":").append(poc.isLayer2Verified()).append(",");
                sb.append("\"layer3\":").append(poc.isLayer3Verified()).append(",");
                sb.append("\"code\":\"").append(escape(poc.getPocCode())).append("\"");
                if (poc.getVerificationError() != null) {
                    sb.append(",\"error\":\"").append(escape(poc.getVerificationError())).append("\"");
                }
                sb.append("}");
            }
            sb.append("]");
        }
        if (patches != null) {
            sb.append(",\"patches\":[");
            for (int i = 0; i < patches.size(); i++) {
                SecurityPatch patch = patches.get(i);
                if (i > 0) {
                    sb.append(",");
                }
                sb.append("{");
                String rawPatchVulnId = patch.getVulnerability().getId();
                sb.append("\"vulnerability_id\":\"")
                    .append(escape(normalizeId(rawPatchVulnId))).append("\",");
                sb.append("\"raw_vulnerability_id\":\"")
                    .append(escape(rawPatchVulnId)).append("\",");
                sb.append("\"type\":\"")
                    .append(escape(patch.getVulnerability().getVulnerabilityType())).append("\",");
                sb.append("\"template_id\":\"").append(escape(patch.getTemplateId())).append("\",");
                sb.append("\"status\":\"").append(escape(String.valueOf(patch.getVerificationStatus()))).append("\",");
                sb.append("\"layer1\":").append(patch.isLayer1Verified()).append(",");
                sb.append("\"layer2\":").append(patch.isLayer2Verified()).append(",");
                sb.append("\"layer3\":").append(patch.isLayer3Verified()).append(",");
                sb.append("\"vulnerable_code\":\"").append(escape(patch.getVulnerableCode())).append("\",");
                sb.append("\"patched_code\":\"").append(escape(patch.getPatchedCode())).append("\"");
                sb.append("}");
            }
            sb.append("]");
        }

        if (pocError != null) {
            sb.append(",\"poc_error\":\"").append(escape(pocError)).append("\"");
        }
        if (patchError != null) {
            sb.append(",\"patch_error\":\"").append(escape(patchError)).append("\"");
        }
        if (joernReport != null) {
            sb.append(",\"joern\":");
            sb.append(mapToJson(joernReport));
        }
        if (enhancedReport != null) {
            sb.append(",\"enhanced\":");
            sb.append(mapToJson(enhancedReport));
        }

        sb.append("}");
        return sb.toString();
    }

    private static String normalizeId(String id) {
        if (id == null) {
            return "";
        }
        return id.replace("/", ".");
    }

    private static String mapToJson(Map<?, ?> map) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        int idx = 0;
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (idx++ > 0) {
                sb.append(",");
            }
            sb.append("\"").append(escape(String.valueOf(entry.getKey()))).append("\":");
            sb.append(valueToJson(entry.getValue()));
        }
        sb.append("}");
        return sb.toString();
    }

    private static String listToJson(List<?> items) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) {
                sb.append(",");
            }
            sb.append(valueToJson(items.get(i)));
        }
        sb.append("]");
        return sb.toString();
    }

    private static String valueToJson(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof Map) {
            return mapToJson((Map<?, ?>) value);
        }
        if (value instanceof List) {
            return listToJson((List<?>) value);
        }
        if (value instanceof Number || value instanceof Boolean) {
            return value.toString();
        }
        return "\"" + escape(String.valueOf(value)) + "\"";
    }

    private static Map<String, Object> runEnhancedPipeline(String sourcePath, boolean includePatches) {
        Map<String, Object> report = new HashMap<>();
        report.put("analysis_method", "enhanced_scanner");
        if (sourcePath == null || sourcePath.isEmpty()) {
            report.put("success", false);
            report.put("error", "Source file required for enhanced scan");
            return report;
        }

        Path sourceFile = Paths.get(sourcePath);
        if (!Files.exists(sourceFile)) {
            report.put("success", false);
            report.put("error", "Source file not found: " + sourceFile);
            return report;
        }

        String source;
        try {
            source = new String(Files.readAllBytes(sourceFile), StandardCharsets.UTF_8);
        } catch (IOException exc) {
            report.put("success", false);
            report.put("error", "Failed to read source: " + exc.getMessage());
            return report;
        }

        ClassVulnerabilityScanner scanner = new ClassVulnerabilityScanner();
        List<ClassVulnerabilityScanner.Vulnerability> pattern = scanner.scanPatternBased(source);
        List<ClassVulnerabilityScanner.Vulnerability> semantic = scanner.scanSemantic(source);
        List<ClassVulnerabilityScanner.Vulnerability> taint = scanner.scanTaintTracking(source);
        List<ClassVulnerabilityScanner.Vulnerability> ast = new ArrayList<>();

        AstParseResult astResult = tryParseCompilationUnit(sourceFile);
        if (astResult != null) {
            ast = scanner.scanAST(astResult.unit, astResult.trees);
        }

        List<ClassVulnerabilityScanner.Vulnerability> ensemble = scanner.scanEnsemble(source, ast);

        Map<String, Object> methodCounts = new HashMap<>();
        methodCounts.put("pattern", pattern.size());
        methodCounts.put("semantic", semantic.size());
        methodCounts.put("taint", taint.size());
        methodCounts.put("ast", ast.size());
        methodCounts.put("ensemble", ensemble.size());

        report.put("success", true);
        report.put("source", sourceFile.toString());
        report.put("method_counts", methodCounts);
        report.put("ensemble_count", ensemble.size());
        report.put("ensemble", toFindingMaps(ensemble));

        if (includePatches) {
            EnhancedPatchSynthesizer synthesizer = new EnhancedPatchSynthesizer();
            List<Map<String, Object>> patchResults = new ArrayList<>();
            int successCount = 0;
            for (ClassVulnerabilityScanner.Vulnerability vuln : ensemble) {
                if (vuln.line <= 0) {
                    continue;
                }
                EnhancedPatchSynthesizer.PatchResult result = synthesizer.generatePatch(vuln, source);
                Map<String, Object> patch = new HashMap<>();
                patch.put("cwe", vuln.cwe);
                patch.put("type", vuln.type);
                patch.put("line", vuln.line);
                patch.put("success", result.success);
                patch.put("message", result.message);
                if (result.patchedCode != null) {
                    patch.put("patched_code", result.patchedCode);
                }
                if (result.success) {
                    successCount += 1;
                }
                patchResults.add(patch);
            }
            report.put("patches", patchResults);
            report.put("patch_count", patchResults.size());
            report.put("patch_success_count", successCount);
        }

        return report;
    }

    private static List<Map<String, Object>> toFindingMaps(List<ClassVulnerabilityScanner.Vulnerability> findings) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (ClassVulnerabilityScanner.Vulnerability vuln : findings) {
            Map<String, Object> entry = new HashMap<>();
            entry.put("type", vuln.type);
            entry.put("cwe", vuln.cwe);
            entry.put("line", vuln.line);
            entry.put("confidence", vuln.confidence);
            entry.put("severity", vuln.severity);
            entry.put("evidence", vuln.evidence);
            result.add(entry);
        }
        return result;
    }

    private static AstParseResult tryParseCompilationUnit(Path sourceFile) {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            return null;
        }
        StandardJavaFileManager fileManager = compiler.getStandardFileManager(null, null, null);
        try {
            Iterable<? extends JavaFileObject> files = fileManager.getJavaFileObjects(sourceFile.toFile());
            JavacTask task = (JavacTask) compiler.getTask(
                null,
                fileManager,
                null,
                Arrays.asList("-proc:none"),
                null,
                files
            );
            Iterable<? extends CompilationUnitTree> units = task.parse();
            CompilationUnitTree unit = units.iterator().hasNext() ? units.iterator().next() : null;
            if (unit == null) {
                return null;
            }
            return new AstParseResult(unit, Trees.instance(task));
        } catch (Exception exc) {
            return null;
        } finally {
            try {
                fileManager.close();
            } catch (IOException ignored) {
            }
        }
    }

    private static class AstParseResult {
        private final CompilationUnitTree unit;
        private final Trees trees;

        private AstParseResult(CompilationUnitTree unit, Trees trees) {
            this.unit = unit;
            this.trees = trees;
        }
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
}
