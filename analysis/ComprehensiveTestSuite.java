import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

/**
 * Comprehensive Test Suite for Bean-Vulnerable
 * Uses real sample files + CLI integration (no randomness).
 */
public class ComprehensiveTestSuite {

    private static final Path REPO_ROOT = Paths.get("").toAbsolutePath();
    private static final Path CLI_PATH = REPO_ROOT.resolve("src/core/bean_vuln_cli.py");
    private static final Path AEG_JAR = REPO_ROOT.resolve("java/aeg-lite/target/aeg-lite-java-0.1.0-all.jar");
    private static final Path REPORT_DIR = REPO_ROOT.resolve("analysis/test_suite_runs");
    private static final double MIN_CONF = 0.60;

    private static int testsPassed = 0;
    private static int testsFailed = 0;
    private static int testsSkipped = 0;
    private static final List<TestResult> results = new ArrayList<>();
    private static final Map<String, AnalysisResult> cachedAnalysis = new HashMap<>();

    public static void main(String[] args) {
        System.out.println("╔════════════════════════════════════════════════════════════════╗");
        System.out.println("║       Comprehensive Test Suite - Bean-Vulnerable              ║");
        System.out.println("║       Real CLI + Samples | Coverage Validation                ║");
        System.out.println("╚════════════════════════════════════════════════════════════════╝\n");

        try {
            Files.createDirectories(REPORT_DIR);
        } catch (IOException e) {
            System.err.println("Failed to create report directory: " + e.getMessage());
            System.exit(2);
        }

        // SQL Injection Tests
        test("CWE-89: SQL Injection Detection",
            () -> expectVuln("tests/samples/VUL001_SQLInjection_Basic.java", "sql_injection", MIN_CONF));
        test("CWE-89: SQL Injection - Advanced Patterns",
            () -> expectVuln("tests/samples/VUL_ADVANCED_TaintTracking.java", "sql_injection", MIN_CONF));
        test("CWE-89: SQL Injection - Parameterized Query (Safe)",
            () -> expectNoVuln("tests/samples/SAFE_SQLInjection_Parameterized.java", "sql_injection"));

        // Command Injection Tests (ProcessBuilder is treated as risky by heuristic)
        test("CWE-78: OS Command Injection Detection (Runtime.exec)",
            () -> expectVuln("tests/samples/VUL003_CommandInjection_Runtime.java", "command_injection", MIN_CONF));
        test("CWE-78: Command Injection (ProcessBuilder - Conservative)",
            () -> expectGated("tests/samples/VUL004_CommandInjection_ProcessBuilder.java", "command_injection"));

        // XSS Tests
        test("CWE-79: Cross-Site Scripting Detection",
            () -> expectVuln("tests/samples/VUL006_XSS_ServletResponse.java", "xss", MIN_CONF));
        test("CWE-79: XSS Prevention - Proper Escaping",
            () -> expectNoVuln("tests/samples/SAFE_XSS_EncodeForHtml.java", "xss"));

        // Path Traversal Tests
        test("CWE-22: Path Traversal Detection",
            () -> expectVuln("tests/samples/VUL005_PathTraversal_FileRead.java", "path_traversal", MIN_CONF));
        test("CWE-22: Path Traversal Prevention - Canonical Path",
            () -> expectNoVuln("tests/samples/SAFE_PathTraversal_Canonical.java", "path_traversal"));

        // Cryptography Tests
        test("CWE-327: Weak Cryptography Detection (DES)",
            () -> expectVuln("tests/samples/VUL011_WeakCrypto_DES.java", "weak_crypto", MIN_CONF));

        // CSRF Tests
        test("CWE-352: CSRF Token Validation Required",
            () -> expectVuln("tests/samples/VUL010_CSRF_NoToken.java", "csrf", MIN_CONF));

        // Hardcoded Secrets Tests
        test("CWE-798: Hardcoded Credentials Detection",
            () -> expectVuln("tests/samples/VUL012_HardcodedCredentials.java", "hardcoded_credentials", MIN_CONF));

        // File Upload / Certificate Validation (not supported in current heuristics)
        skip("CWE-434: File Upload Validation (not implemented)");
        skip("CWE-295: Certificate Validation (not implemented)");

        // Integer Overflow Tests
        test("CWE-190: Integer Overflow Detection",
            () -> expectVuln("tests/samples/VUL022_IntegerOverflow.java", "integer_overflow", MIN_CONF));

        // XXE Tests
        test("CWE-611: XML External Entity (XXE)",
            () -> expectVuln("tests/samples/VUL008_XXE_DocumentBuilder.java", "xxe", MIN_CONF));

        // Additional coverage
        test("CWE-502: Deserialization",
            () -> expectVuln("tests/samples/VUL009_Deserialization_ObjectInputStream.java", "deserialization", MIN_CONF));
        test("CWE-918: SSRF",
            () -> expectVuln("tests/samples/VUL025_SSRF_URLConnection.java", "ssrf", MIN_CONF));
        test("CWE-470: Reflection Injection",
            () -> expectGated("tests/samples/VUL023_ReflectionInjection.java", "reflection_injection"));
        test("CWE-94: EL Injection",
            () -> expectVuln("tests/samples/VUL024_ExpressionLanguageInjection.java", "el_injection", MIN_CONF));
        test("CWE-643: XPath Injection",
            () -> expectVuln("tests/samples/VUL027_XPath_Injection.java", "xpath_injection", MIN_CONF));
        test("CWE-94: ScriptEngine Eval Injection (mapped to EL)",
            () -> expectGated("tests/samples/VUL028_ScriptEngine_EvalInjection.java", "el_injection"));
        test("CWE-90: LDAP Injection",
            () -> expectVuln("tests/samples/VUL007_LDAP_Injection.java", "ldap_injection", MIN_CONF));
        test("CWE-113: HTTP Response Splitting",
            () -> expectVuln("tests/samples/VUL018_HTTPResponseSplitting.java", "http_response_splitting", MIN_CONF));
        test("CWE-501: Trust Boundary Violation",
            () -> expectVuln("tests/samples/VUL019_TrustBoundaryViolation.java", "trust_boundary_violation", MIN_CONF));
        test("CWE-338: Insecure Randomness",
            () -> expectVuln("tests/samples/VUL016_InsecureRandomness.java", "insecure_randomness", MIN_CONF));
        test("CWE-117: Log Injection",
            () -> expectVuln("tests/samples/VUL017_LogInjection.java", "log_injection", MIN_CONF));
        test("CWE-384: Session Fixation",
            () -> expectVuln("tests/samples/VUL015_SessionFixation.java", "session_fixation", MIN_CONF));
        test("CWE-362: Race Condition",
            () -> expectVuln("tests/samples/VUL014_RaceCondition_SharedResource.java", "race_condition", MIN_CONF));
        test("CWE-404: Resource Leak",
            () -> expectVuln("tests/samples/VUL020_ResourceLeak.java", "resource_leak", MIN_CONF));
        test("CWE-476: Null Pointer Dereference",
            () -> expectVuln("tests/samples/VUL021_NullPointerDereference.java", "null_pointer_dereference", MIN_CONF));
        test("CWE-120: Buffer Overflow",
            () -> expectVuln("tests/samples/VUL013_BufferOverflow_Array.java", "buffer_overflow", MIN_CONF));
        test("Multi-Vuln: Complex Sample",
            () -> expectAtLeast("tests/samples/VUL_COMPLEX_MultiVulnerability.java", 3));

        // Patch Generation Tests (AEG-Lite)
        test("Patch Generation: SQL Injection Fix",
            () -> expectAegPatches("tests/samples/VUL001_SQLInjection_Basic.java", 1));
        test("Patch Generation: Command Injection Fix",
            () -> expectAegPatches("tests/samples/VUL003_CommandInjection_Runtime.java", 1));
        test("Patch Generation: Path Traversal Fix",
            () -> expectAegPatches("tests/samples/VUL005_PathTraversal_FileRead.java", 1));

        // Performance (best-effort)
        test("Performance: Single file analysis < 60s",
            () -> measureSingleAnalysis("tests/samples/VUL001_SQLInjection_Basic.java", 60000));
        test("Scalability: 5 files < 4 min",
            () -> measureMultiAnalysis(
                Arrays.asList(
                    "tests/samples/VUL001_SQLInjection_Basic.java",
                    "tests/samples/VUL006_XSS_ServletResponse.java",
                    "tests/samples/VUL008_XXE_DocumentBuilder.java",
                    "tests/samples/VUL010_CSRF_NoToken.java",
                    "tests/samples/VUL022_IntegerOverflow.java"
                ), 240000));

        printTestSummary();
    }

    // ────────────────────────────────────────────────────────────────
    // Test helpers
    // ────────────────────────────────────────────────────────────────

    static void test(String name, TestCase testCase) {
        try {
            if (testCase.execute()) {
                testsPassed++;
                results.add(new TestResult(name, "PASS", null));
                System.out.println("✓ PASS: " + name);
            } else {
                testsFailed++;
                results.add(new TestResult(name, "FAIL", "Assertion failed"));
                System.out.println("✗ FAIL: " + name);
            }
        } catch (Exception e) {
            testsFailed++;
            results.add(new TestResult(name, "ERROR", e.getMessage()));
            System.out.println("✗ ERROR: " + name + " - " + e.getMessage());
        }
    }

    static void skip(String name) {
        testsSkipped++;
        results.add(new TestResult(name, "SKIP", "Not supported in current heuristic set"));
        System.out.println("⟳ SKIP: " + name);
    }

    static boolean expectVuln(String relativePath, String vulnType, double minConfidence) throws Exception {
        AnalysisResult result = analyzeSample(relativePath);
        return result.vulnerabilitiesFound.contains(vulnType) && result.confidence >= minConfidence;
    }

    static boolean expectNoVuln(String relativePath, String vulnType) throws Exception {
        AnalysisResult result = analyzeSample(relativePath);
        return !result.vulnerabilitiesFound.contains(vulnType);
    }

    static boolean expectGated(String relativePath, String vulnType) throws Exception {
        AnalysisResult result = analyzeSample(relativePath);
        if (result.vulnerabilitiesFound.contains(vulnType)) {
            return true;
        }
        return result.gatedDropped.contains(vulnType);
    }

    static boolean expectAtLeast(String relativePath, int count) throws Exception {
        AnalysisResult result = analyzeSample(relativePath);
        return result.vulnerabilitiesFound.size() >= count;
    }

    static boolean expectAegPatches(String relativePath, int minPatches) throws Exception {
        AegLiteResult result = runAegLite(relativePath, true, false);
        if (result.patchCount < minPatches) {
            return false;
        }
        return result.allPatchesLayer1Ok;
    }

    static boolean measureSingleAnalysis(String relativePath, long maxMillis) throws Exception {
        long start = System.currentTimeMillis();
        analyzeSample(relativePath);
        long elapsed = System.currentTimeMillis() - start;
        return elapsed <= maxMillis;
    }

    static boolean measureMultiAnalysis(List<String> paths, long maxMillis) throws Exception {
        long start = System.currentTimeMillis();
        for (String path : paths) {
            analyzeSample(path);
        }
        long elapsed = System.currentTimeMillis() - start;
        return elapsed <= maxMillis;
    }

    // ────────────────────────────────────────────────────────────────
    // CLI integration
    // ────────────────────────────────────────────────────────────────

    static AnalysisResult analyzeSample(String relativePath) throws Exception {
        if (cachedAnalysis.containsKey(relativePath)) {
            return cachedAnalysis.get(relativePath);
        }
        Path samplePath = REPO_ROOT.resolve(relativePath);
        if (!Files.exists(samplePath)) {
            throw new IllegalArgumentException("Sample not found: " + samplePath);
        }
        Path outPath = REPORT_DIR.resolve(samplePath.getFileName().toString() + ".json");
        List<String> cmd = new ArrayList<>();
        cmd.add(resolvePython());
        cmd.add(CLI_PATH.toString());
        cmd.add(samplePath.toString());
        cmd.add("--summary");
        cmd.add("--aeg-lite-java");
        cmd.add("--aeg-lite-pocs");
        cmd.add("--aeg-lite-patches");
        cmd.add("--out");
        cmd.add(outPath.toString());

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.environment().put("PYTHONPATH", REPO_ROOT.resolve("src").toString());
        pb.redirectErrorStream(true);
        Process process = pb.start();
        String output = readProcessOutput(process);
        int exit = process.waitFor();
        if (exit != 0) {
            throw new RuntimeException("CLI failed: " + output);
        }
        String jsonText = Files.readString(outPath, StandardCharsets.UTF_8);
        AnalysisResult result = parseAnalysisResult(jsonText);
        cachedAnalysis.put(relativePath, result);
        return result;
    }

    static AegLiteResult runAegLite(String relativePath, boolean genPatches, boolean genPocs) throws Exception {
        ensureAegJar();
        Path samplePath = REPO_ROOT.resolve(relativePath);
        if (!Files.exists(samplePath)) {
            throw new IllegalArgumentException("Sample not found: " + samplePath);
        }
        Path classesDir = Files.createTempDirectory("aeg_test_classes_");
        List<String> javacCmd = Arrays.asList(
            "javac", "-encoding", "UTF-8", "-g", "-d", classesDir.toString(), samplePath.toString()
        );
        ProcessBuilder javac = new ProcessBuilder(javacCmd);
        javac.redirectErrorStream(true);
        Process compile = javac.start();
        String compileOut = readProcessOutput(compile);
        if (compile.waitFor() != 0) {
            throw new RuntimeException("javac failed: " + compileOut);
        }

        List<String> cmd = new ArrayList<>();
        cmd.add("java");
        cmd.add("-cp");
        cmd.add(AEG_JAR.toString());
        cmd.add("com.beanvulnerable.aeg.AegLiteRunner");
        cmd.add("--classes-dir");
        cmd.add(classesDir.toString());
        cmd.add("--source");
        cmd.add(samplePath.toString());
        if (genPatches) cmd.add("--generate-patches");
        if (genPocs) cmd.add("--generate-pocs");

        ProcessBuilder run = new ProcessBuilder(cmd);
        run.redirectErrorStream(true);
        Process process = run.start();
        String output = readProcessOutput(process);
        int exit = process.waitFor();
        if (exit != 0) {
            throw new RuntimeException("AEG-Lite failed: " + output);
        }
        return parseAegResult(output.trim());
    }

    static String resolvePython() {
        Path venvPython = REPO_ROOT.resolve("venv_cli/bin/python");
        if (Files.exists(venvPython)) {
            return venvPython.toString();
        }
        return "python3";
    }

    static void ensureAegJar() throws IOException, InterruptedException {
        if (Files.exists(AEG_JAR)) {
            return;
        }
        List<String> cmd = Arrays.asList("mvn", "-f", "java/aeg-lite/pom.xml", "-DskipTests", "package");
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        String output = readProcessOutput(process);
        if (process.waitFor() != 0 || !Files.exists(AEG_JAR)) {
            throw new RuntimeException("Failed to build AEG-Lite jar: " + output);
        }
    }

    static String readProcessOutput(Process process) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append('\n');
            }
        }
        return sb.toString();
    }

    // ────────────────────────────────────────────────────────────────
    // JSON parsing
    // ────────────────────────────────────────────────────────────────

    static AnalysisResult parseAnalysisResult(String jsonText) throws Exception {
        Map<String, Object> result;
        Object parsed = parseJson(jsonText);
        if (parsed instanceof List) {
            List<?> list = (List<?>) parsed;
            if (list.isEmpty()) {
                throw new RuntimeException("Empty JSON result");
            }
            result = (Map<String, Object>) list.get(0);
        } else if (parsed instanceof Map) {
            result = (Map<String, Object>) parsed;
        } else {
            result = parseFallback(jsonText);
        }
        boolean detected = getBoolean(result, "vulnerability_detected");
        double confidence = getDouble(result, "confidence");
        Set<String> found = new LinkedHashSet<>(getStringList(result, "vulnerabilities_found"));
        Set<String> dropped = new LinkedHashSet<>();
        Object gatingObj = result.get("taint_gating");
        if (gatingObj instanceof Map) {
            Object droppedList = ((Map<?, ?>) gatingObj).get("dropped");
            if (droppedList instanceof List) {
                for (Object entry : (List<?>) droppedList) {
                    if (entry instanceof Map) {
                        Object vuln = ((Map<?, ?>) entry).get("vulnerability");
                        if (vuln != null) {
                            dropped.add(String.valueOf(vuln));
                        }
                    }
                }
            }
        }
        if (dropped.isEmpty()) {
            dropped.addAll(extractDroppedList(jsonText));
        }
        return new AnalysisResult(detected, confidence, found, dropped);
    }

    static AegLiteResult parseAegResult(String jsonText) throws Exception {
        Map<String, Object> result;
        Object parsed = parseJson(jsonText);
        if (parsed instanceof Map) {
            result = (Map<String, Object>) parsed;
        } else {
            result = parseFallback(jsonText);
        }
        int patchCount = (int) getDouble(result, "patch_count");
        boolean allLayer1 = true;
        Object patchesObj = result.get("patches");
        if (patchesObj instanceof List) {
            for (Object patch : (List<?>) patchesObj) {
                if (patch instanceof Map) {
                    boolean layer1 = getBoolean((Map<String, Object>) patch, "layer1");
                    if (!layer1) {
                        allLayer1 = false;
                        break;
                    }
                }
            }
        }
        return new AegLiteResult(patchCount, allLayer1);
    }

    static Object parseJson(String jsonText) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("javascript");
        if (engine == null) {
            return null;
        }
        return engine.eval("Java.asJSONCompatible(" + jsonText + ")");
    }

    static Map<String, Object> parseFallback(String jsonText) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("vulnerability_detected", extractBoolean(jsonText, "vulnerability_detected"));
        result.put("confidence", extractNumber(jsonText, "confidence"));
        result.put("patch_count", extractNumber(jsonText, "patch_count"));
        result.put("vulnerabilities_found", extractStringList(jsonText, "vulnerabilities_found"));
        return result;
    }

    static Set<String> extractDroppedList(String jsonText) {
        Set<String> dropped = new LinkedHashSet<>();
        Matcher droppedBlock = Pattern.compile("\"dropped\"\\s*:\\s*\\[(.*?)\\]", Pattern.DOTALL)
            .matcher(jsonText);
        if (!droppedBlock.find()) {
            return dropped;
        }
        String body = droppedBlock.group(1);
        Matcher vuln = Pattern.compile("\"vulnerability\"\\s*:\\s*\"(.*?)\"").matcher(body);
        while (vuln.find()) {
            dropped.add(vuln.group(1));
        }
        return dropped;
    }

    static boolean extractBoolean(String jsonText, String field) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:\\s*(true|false)").matcher(jsonText);
        return m.find() && "true".equalsIgnoreCase(m.group(1));
    }

    static double extractNumber(String jsonText, String field) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:\\s*([-0-9.Ee]+)").matcher(jsonText);
        if (m.find()) {
            try {
                return Double.parseDouble(m.group(1));
            } catch (NumberFormatException ignored) {
                return 0.0;
            }
        }
        return 0.0;
    }

    static List<String> extractStringList(String jsonText, String field) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:\\s*\\[(.*?)\\]", Pattern.DOTALL)
            .matcher(jsonText);
        if (!m.find()) {
            return Collections.emptyList();
        }
        String body = m.group(1);
        Matcher item = Pattern.compile("\"(.*?)\"").matcher(body);
        List<String> values = new ArrayList<>();
        while (item.find()) {
            values.add(item.group(1));
        }
        return values;
    }

    static boolean getBoolean(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        if (value instanceof String) {
            return Boolean.parseBoolean((String) value);
        }
        return false;
    }

    static double getDouble(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value instanceof Number) {
            return ((Number) value).doubleValue();
        }
        if (value instanceof String) {
            try {
                return Double.parseDouble((String) value);
            } catch (NumberFormatException ignored) {
                return 0.0;
            }
        }
        return 0.0;
    }

    static List<String> getStringList(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value instanceof List) {
            List<String> values = new ArrayList<>();
            for (Object item : (List<?>) value) {
                if (item != null) {
                    values.add(String.valueOf(item));
                }
            }
            return values;
        }
        if (value instanceof String) {
            return Arrays.asList((String) value);
        }
        return Collections.emptyList();
    }

    // ────────────────────────────────────────────────────────────────
    // Summary reporting
    // ────────────────────────────────────────────────────────────────

    static void printTestSummary() {
        System.out.println("\n╔════════════════════════════════════════════════════════════════╗");
        System.out.println("║                      TEST SUMMARY REPORT                      ║");
        System.out.println("╚════════════════════════════════════════════════════════════════╝\n");

        int total = testsPassed + testsFailed + testsSkipped;
        double passRate = total == 0 ? 0.0 : (testsPassed * 100.0) / total;

        System.out.println("OVERALL RESULTS:");
        System.out.printf("├─ Total Tests:       %d\n", total);
        System.out.printf("├─ Passed:            %d ✓\n", testsPassed);
        System.out.printf("├─ Failed:            %d ✗\n", testsFailed);
        System.out.printf("├─ Skipped:           %d ⟳\n", testsSkipped);
        System.out.printf("├─ Pass Rate:         %.1f%%\n", passRate);
        System.out.println("└─ Status:            " + (testsFailed == 0 ? "ALL TESTS PASSING ✓" : "SOME TESTS FAILED ✗"));

        if (testsFailed > 0) {
            System.out.println("\nFAILED TESTS:");
            for (TestResult result : results) {
                if ("FAIL".equals(result.status) || "ERROR".equals(result.status)) {
                    System.out.println(" - " + result.name + " (" + result.status + ")" +
                        (result.error != null ? " : " + result.error : ""));
                }
            }
        }

        System.out.println("\n✓ IMPLEMENTATION: READY FOR VALIDATION\n");
        if (testsFailed > 0) {
            System.exit(1);
        }
    }

    interface TestCase { boolean execute() throws Exception; }

    static class TestResult {
        String name;
        String status;
        String error;
        TestResult(String name, String status, String error) {
            this.name = name;
            this.status = status;
            this.error = error;
        }
    }

    static class AnalysisResult {
        boolean vulnerabilityDetected;
        double confidence;
        Set<String> vulnerabilitiesFound;
        Set<String> gatedDropped;
        AnalysisResult(boolean vulnerabilityDetected, double confidence, Set<String> vulnerabilitiesFound,
                       Set<String> gatedDropped) {
            this.vulnerabilityDetected = vulnerabilityDetected;
            this.confidence = confidence;
            this.vulnerabilitiesFound = vulnerabilitiesFound;
            this.gatedDropped = gatedDropped;
        }
    }

    static class AegLiteResult {
        int patchCount;
        boolean allPatchesLayer1Ok;
        AegLiteResult(int patchCount, boolean allPatchesLayer1Ok) {
            this.patchCount = patchCount;
            this.allPatchesLayer1Ok = allPatchesLayer1Ok;
        }
    }
}
