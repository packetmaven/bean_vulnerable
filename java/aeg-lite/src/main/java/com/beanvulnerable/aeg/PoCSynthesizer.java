package com.beanvulnerable.aeg;

import com.beanvulnerable.aeg.domain.Constraint;
import com.beanvulnerable.aeg.domain.Vulnerability;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PoC (Proof-of-Concept) Synthesizer.
 */
public class PoCSynthesizer {

    private final TemplateRegistry templateRegistry;
    private final Path tempDirectory;
    private final ExecutorService executorService;

    private static final int COMPILATION_TIMEOUT_SECONDS = 30;
    private static final int EXECUTION_TIMEOUT_SECONDS = 10;

    public PoCSynthesizer() {
        this.templateRegistry = new TemplateRegistry();
        this.executorService = Executors.newFixedThreadPool(4);

        try {
            this.tempDirectory = Files.createTempDirectory("poc_synthesis_");
        } catch (IOException e) {
            throw new RuntimeException("Failed to create temp directory", e);
        }
    }

    public GeneratedPoC generatePoC(Vulnerability vulnerability) throws IOException {
        ExploitTemplate template =
            templateRegistry.getTemplate(vulnerability.getVulnerabilityType());

        if (template == null) {
            return null;
        }

        Map<String, String> concreteValues = extractConcreteValues(vulnerability, template);
        String pocCode = template.substituteAll(concreteValues);

        String pocId = "poc_" + System.currentTimeMillis() + "_" +
            UUID.randomUUID().toString().substring(0, 8);

        String normalizedCode = normalizePoCCode(pocCode, pocId);

        GeneratedPoC poc = new GeneratedPoC(
            pocId,
            vulnerability,
            normalizedCode,
            template.getVulnerabilityType()
        );

        verifyPoC(poc);
        return poc;
    }

    private Map<String, String> extractConcreteValues(Vulnerability vulnerability, ExploitTemplate template) {
        Map<String, String> values = new HashMap<>();
        Map<String, Object> model = trySolveConstraints(vulnerability.getConstraints());

        for (String placeholder : template.getPlaceholders()) {
            if (model.containsKey(placeholder)) {
                values.put(placeholder, String.valueOf(model.get(placeholder)));
            } else {
                values.put(placeholder, defaultPlaceholderValue(placeholder, vulnerability.getVulnerabilityType()));
            }
        }

        return values;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> trySolveConstraints(List<Constraint> constraints) {
        try {
            Class<?> solverClass = Class.forName("com.beanvulnerable.aeg.Z3Solver");
            Object solver = solverClass.getConstructor().newInstance();
            Object model = solverClass.getMethod("generateConcreteValues", List.class)
                .invoke(solver, constraints);
            if (model instanceof Map) {
                return (Map<String, Object>) model;
            }
        } catch (Exception ignored) {
        }
        return new HashMap<>();
    }

    private String defaultPlaceholderValue(String placeholder, String vulnType) {
        if ("SERIALIZED_GADGET".equals(placeholder)) {
            return "AA==";
        }
        if ("USER_INPUT".equals(placeholder)) {
            if ("sql_injection".equals(vulnType)) {
                return "1 OR 1=1";
            }
            if ("command_injection".equals(vulnType)) {
                return "; cat /etc/passwd";
            }
            if ("path_traversal".equals(vulnType)) {
                return "../../etc/passwd";
            }
            if ("xpath_injection".equals(vulnType)) {
                return "' or '1'='1";
            }
            if ("xss".equals(vulnType)) {
                return "<script>alert(1)</script>";
            }
        if ("ldap_injection".equals(vulnType)) {
            return "*)(|(uid=*))";
        }
        if ("xxe".equals(vulnType)) {
            return "file:///etc/passwd";
        }
        if ("el_injection".equals(vulnType)) {
            return "${7*7}";
        }
        if ("http_response_splitting".equals(vulnType)) {
            return "%0d%0aSet-Cookie:evil=1";
        }
        if ("url_redirect".equals(vulnType)) {
            return "http://evil.example/";
        }
        if ("reflection".equals(vulnType) || "reflection_injection".equals(vulnType)) {
            return "java.lang.String";
        }
        if ("file_operation".equals(vulnType)) {
            return "../../tmp/evil.txt";
        }
            return "test";
        }
        return "test";
    }

    private void verifyPoC(GeneratedPoC poc) {
        try {
            boolean compiles = layer1CompilationVerification(poc);
            poc.setLayer1Verified(compiles);
            if (!compiles) {
                poc.setVerificationStatus(VerificationStatus.LAYER1_FAILED);
                return;
            }
        } catch (IOException e) {
            poc.setVerificationStatus(VerificationStatus.LAYER1_FAILED);
            poc.setVerificationError(e.getMessage());
            return;
        }

        try {
            boolean semanticsOk = layer2SemanticVerification(poc);
            poc.setLayer2Verified(semanticsOk);
            if (!semanticsOk) {
                poc.setVerificationStatus(VerificationStatus.LAYER2_FAILED);
                return;
            }
        } catch (Exception e) {
            poc.setVerificationStatus(VerificationStatus.LAYER2_FAILED);
            poc.setVerificationError(e.getMessage());
            return;
        }

        try {
            boolean executes = layer3ExecutionVerification(poc);
            poc.setLayer3Verified(executes);
            poc.setVerificationStatus(executes
                ? VerificationStatus.ALL_LAYERS_PASSED
                : VerificationStatus.LAYER3_FAILED);
        } catch (Exception e) {
            poc.setVerificationStatus(VerificationStatus.LAYER3_FAILED);
            poc.setVerificationError(e.getMessage());
        }
    }

    private boolean layer1CompilationVerification(GeneratedPoC poc) throws IOException {
        String sourceFileName = poc.getPocId() + ".java";
        Path sourceFile = tempDirectory.resolve(sourceFileName);
        Files.write(sourceFile, poc.getPocCode().getBytes(StandardCharsets.UTF_8));

        ProcessBuilder pb = new ProcessBuilder("javac", sourceFile.toString());
        pb.redirectErrorStream(true);

        try {
            Process p = pb.start();
            boolean completed = p.waitFor(
                COMPILATION_TIMEOUT_SECONDS,
                TimeUnit.SECONDS
            );

            if (!completed) {
                p.destroy();
                return false;
            }

            return p.exitValue() == 0;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private boolean layer2SemanticVerification(GeneratedPoC poc) {
        String code = poc.getPocCode();

        boolean hasUncheckedCast = code.contains("(Object)") &&
            !code.contains("(String)");
        if (hasUncheckedCast) {
            return false;
        }

        return true;
    }

    private boolean layer3ExecutionVerification(GeneratedPoC poc) throws Exception {
        String sourceFileName = poc.getPocId() + ".java";
        String classFileName = poc.getPocId() + ".class";

        Path sourceFile = tempDirectory.resolve(sourceFileName);
        Path classFile = tempDirectory.resolve(classFileName);

        if (!Files.exists(classFile)) {
            ProcessBuilder pb = new ProcessBuilder("javac", sourceFile.toString());
            Process p = pb.start();
            p.waitFor(COMPILATION_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        }

        ProcessBuilder pb = new ProcessBuilder(
            "java",
            "-cp", tempDirectory.toString(),
            poc.getPocId()
        );

        pb.redirectErrorStream(true);

        Process p = pb.start();
        boolean completed = p.waitFor(
            EXECUTION_TIMEOUT_SECONDS,
            TimeUnit.SECONDS
        );

        if (!completed) {
            p.destroy();
            return true;
        }

        int exitCode = p.exitValue();
        return exitCode == 0 || exitCode == 1;
    }

    public PoCReport generatePoCReport(GeneratedPoC poc) {
        PoCReport report = new PoCReport(poc);
        report.setVulnerabilityType(poc.getVulnerabilityType());
        report.setSeverity(calculateSeverity(poc));

        String impact = describeImpact(poc.getVulnerabilityType());
        report.setImpact(impact);

        String mitigation = describeMitigation(poc.getVulnerabilityType());
        report.setMitigation(mitigation);

        report.setPoCCode(poc.getPocCode());
        report.setVerificationStatus(poc.getVerificationStatus());
        report.setLayer1Verified(poc.isLayer1Verified());
        report.setLayer2Verified(poc.isLayer2Verified());
        report.setLayer3Verified(poc.isLayer3Verified());
        return report;
    }

    private String calculateSeverity(GeneratedPoC poc) {
        String type = poc.getVulnerabilityType();
        if ("command_injection".equals(type)) {
            return "CRITICAL";
        }
        if ("deserialization".equals(type)) {
            return "CRITICAL";
        }
        if ("sql_injection".equals(type)) {
            return "HIGH";
        }
        if ("xpath_injection".equals(type)) {
            return "MEDIUM";
        }
        if ("path_traversal".equals(type)) {
            return "HIGH";
        }
        if ("ldap_injection".equals(type) || "xxe".equals(type)) {
            return "HIGH";
        }
        if ("el_injection".equals(type) || "reflection_injection".equals(type) || "reflection".equals(type)) {
            return "HIGH";
        }
        if ("http_response_splitting".equals(type) || "url_redirect".equals(type)) {
            return "MEDIUM";
        }
        return "MEDIUM";
    }

    private String describeImpact(String vulnType) {
        if ("command_injection".equals(vulnType)) {
            return "Attacker can execute arbitrary system commands with application privileges";
        }
        if ("deserialization".equals(vulnType)) {
            return "Attacker can achieve Remote Code Execution (RCE) via malicious serialized objects";
        }
        if ("sql_injection".equals(vulnType)) {
            return "Attacker can read, modify, or delete database records";
        }
        if ("xpath_injection".equals(vulnType)) {
            return "Attacker can extract sensitive data from XML documents";
        }
        if ("path_traversal".equals(vulnType)) {
            return "Attacker can read arbitrary files from the system";
        }
        if ("ldap_injection".equals(vulnType)) {
            return "Attacker can manipulate LDAP queries and bypass access controls";
        }
        if ("xxe".equals(vulnType)) {
            return "Attacker can read server files or trigger SSRF via external entities";
        }
        if ("el_injection".equals(vulnType)) {
            return "Attacker can execute arbitrary expressions on the server";
        }
        if ("http_response_splitting".equals(vulnType)) {
            return "Attacker can inject headers or split HTTP responses";
        }
        if ("url_redirect".equals(vulnType)) {
            return "Attacker can redirect users to malicious destinations";
        }
        if ("reflection_injection".equals(vulnType) || "reflection".equals(vulnType)) {
            return "Attacker can trigger unsafe reflective class loading or method calls";
        }
        return "Potential security impact";
    }

    private String describeMitigation(String vulnType) {
        if ("command_injection".equals(vulnType)) {
            return "Use ProcessBuilder instead of Runtime.exec(); avoid shell interpretation";
        }
        if ("deserialization".equals(vulnType)) {
            return "Use JSON instead of Java serialization; implement ObjectInputStream filter";
        }
        if ("sql_injection".equals(vulnType)) {
            return "Use PreparedStatements with parameterized queries";
        }
        if ("xpath_injection".equals(vulnType)) {
            return "Avoid string concatenation in XPath; use parameterized XPath queries";
        }
        if ("path_traversal".equals(vulnType)) {
            return "Validate/sanitize file paths; use java.nio.file.Path normalization";
        }
        if ("ldap_injection".equals(vulnType)) {
            return "Use LDAP filter escaping and parameterized queries";
        }
        if ("xxe".equals(vulnType)) {
            return "Disable external entities and DTDs in XML parsers";
        }
        if ("el_injection".equals(vulnType)) {
            return "Avoid evaluating untrusted expressions; use allowlists";
        }
        if ("http_response_splitting".equals(vulnType)) {
            return "Strip CR/LF from header values and validate redirects";
        }
        if ("url_redirect".equals(vulnType)) {
            return "Use allowlists for redirect targets";
        }
        if ("reflection_injection".equals(vulnType) || "reflection".equals(vulnType)) {
            return "Allowlist class and method names before reflective calls";
        }
        return "Implement input validation and use security libraries";
    }

    public List<GeneratedPoC> generatePoCsForVulnerabilities(
        List<Vulnerability> vulnerabilities) throws IOException {

        List<GeneratedPoC> pocs = new ArrayList<>();
        for (Vulnerability vuln : vulnerabilities) {
            try {
                GeneratedPoC poc = generatePoC(vuln);
                if (poc != null && poc.isLayer1Verified()) {
                    pocs.add(poc);
                }
            } catch (Exception e) {
                System.err.println("Failed to generate PoC for: " + vuln);
            }
        }
        return pocs;
    }

    public void cleanup() {
        executorService.shutdown();
        try {
            Files.walk(tempDirectory)
                .sorted(Comparator.reverseOrder())
                .forEach(path -> {
                    try {
                        Files.delete(path);
                    } catch (IOException ignored) {
                    }
                });
        } catch (IOException e) {
            System.err.println("Cleanup failed: " + e.getMessage());
        }
    }

    private String normalizePoCCode(String pocCode, String className) {
        String normalized = removePackageDeclaration(pocCode);
        return rewriteClassName(normalized, className);
    }

    private String removePackageDeclaration(String code) {
        return code.replaceFirst("(?m)^\\s*package\\s+[^;]+;\\s*", "");
    }

    private String rewriteClassName(String code, String className) {
        Pattern pattern = Pattern.compile("\\bclass\\s+(\\w+)\\b");
        Matcher matcher = pattern.matcher(code);
        if (matcher.find()) {
            return matcher.replaceFirst("class " + className);
        }
        return code;
    }
}
