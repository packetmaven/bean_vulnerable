package com.beanvulnerable.aeg;

import com.beanvulnerable.aeg.domain.MethodAnalysis;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Patch Synthesizer.
 */
public class PatchSynthesizer {

    private final PatchTemplateRepository templateRepository;
    private final LLMClient llmClient;
    private final Path tempDirectory;

    private static final int LLM_TIMEOUT_SECONDS = 60;

    public PatchSynthesizer() {
        this.templateRepository = new PatchTemplateRepository();
        this.llmClient = new LLMClient();

        try {
            this.tempDirectory = Files.createTempDirectory("patch_synthesis_");
        } catch (IOException e) {
            throw new RuntimeException("Failed to create temp directory", e);
        }
    }

    public SecurityPatch generatePatchFromTemplate(
        Vulnerability vulnerability,
        String vulnerableCode) throws IOException {

        List<PatchTemplate> templates =
            templateRepository.findTemplates(vulnerability.getVulnerabilityType());

        if (templates.isEmpty()) {
            return null;
        }

        for (PatchTemplate template : templates) {
            if (!matchesSinkHint(vulnerability, template)) {
                continue;
            }
            Pattern pattern = Pattern.compile(template.getVulnerablePattern());
            Matcher matcher = pattern.matcher(vulnerableCode);
            if (!matcher.find()) {
                continue;
            }
            String patchedCode = matcher.replaceAll(template.getFixedPattern());
            patchedCode = ensurePathAllowlistHelper(patchedCode);
            patchedCode = ensureXPathEscapeHelper(patchedCode);
            patchedCode = ensureLdapEscapeHelper(patchedCode);
            patchedCode = ensureHeaderSanitizerHelper(patchedCode);
            patchedCode = ensureElSanitizerHelper(patchedCode);
            patchedCode = ensureXxeHardeningHelper(patchedCode);
            patchedCode = ensureReflectionAllowlistHelper(patchedCode);
            if (patchedCode.equals(vulnerableCode)) {
                continue;
            }

            SecurityPatch patch = new SecurityPatch(
                vulnerability,
                vulnerableCode,
                patchedCode,
                "template_based",
                template.getTemplateId()
            );

            verifyPatch(patch);
            if (patch.isLayer1Verified()) {
                return patch;
            }
        }

        return null;
    }

    public SecurityPatch generatePatchFromLLM(
        Vulnerability vulnerability,
        String vulnerableCode,
        MethodAnalysis methodAnalysis) throws Exception {

        String prompt = buildLLMPrompt(vulnerability, vulnerableCode);

        LLMResponse response = llmClient.generatePatch(
            prompt,
            LLM_TIMEOUT_SECONDS
        );

        if (!response.isSuccessful()) {
            return null;
        }

        String patchedCode = extractPatchCode(response.getContent());

        SecurityPatch patch = new SecurityPatch(
            vulnerability,
            vulnerableCode,
            patchedCode,
            "llm_assisted",
            "claude_" + System.currentTimeMillis()
        );

        verifyPatch(patch);
        return patch;
    }

    private String buildLLMPrompt(Vulnerability vulnerability,
                                  String vulnerableCode) {
        return String.format(
            "You are a Java security expert. Fix the following vulnerable code:%n%n" +
                "Vulnerability Type: %s%n" +
                "Severity: HIGH%n" +
                "Description: %s%n%n" +
                "VULNERABLE CODE:%n" +
                "```java%n" +
                "%s%n" +
                "```%n%n" +
                "Please provide:%n" +
                "1. The fixed code (secure version)%n" +
                "2. Brief explanation of the fix%n" +
                "3. Why it's secure%n%n" +
                "Requirements:%n" +
                "- Fix must compile (valid Java)%n" +
                "- Fix must maintain original functionality%n" +
                "- Fix must eliminate the vulnerability%n" +
                "- Use industry best practices%n",
            vulnerability.getVulnerabilityType(),
            vulnerability.getDescription(),
            vulnerableCode
        );
    }

    private String extractPatchCode(String llmResponse) {
        Pattern pattern = Pattern.compile("```java\\n(.*?)\\n```",
            Pattern.DOTALL);
        Matcher matcher = pattern.matcher(llmResponse);

        if (matcher.find()) {
            return matcher.group(1);
        }

        return llmResponse;
    }

    private void verifyPatch(SecurityPatch patch) {
        try {
            boolean compiles = layer1CompilationVerification(patch);
            patch.setLayer1Verified(compiles);

            if (!compiles) {
                patch.setVerificationStatus(VerificationStatus.LAYER1_FAILED);
                return;
            }
        } catch (IOException e) {
            patch.setVerificationStatus(VerificationStatus.LAYER1_FAILED);
            return;
        }

        try {
            boolean semanticsOk = layer2SemanticVerification(patch);
            patch.setLayer2Verified(semanticsOk);

            if (!semanticsOk) {
                patch.setVerificationStatus(VerificationStatus.LAYER2_FAILED);
                return;
            }
        } catch (Exception e) {
            patch.setVerificationStatus(VerificationStatus.LAYER2_FAILED);
            return;
        }

        try {
            boolean testsPassed = layer3ExecutionVerification(patch);
            patch.setLayer3Verified(testsPassed);

            if (testsPassed) {
                patch.setVerificationStatus(VerificationStatus.ALL_LAYERS_PASSED);
            } else {
                patch.setVerificationStatus(VerificationStatus.LAYER3_FAILED);
            }
        } catch (Exception e) {
            patch.setVerificationStatus(VerificationStatus.LAYER3_FAILED);
        }
    }

    private boolean layer1CompilationVerification(SecurityPatch patch) throws IOException {
        String className = extractPrimaryClassName(patch.getPatchedCode());
        String fileName = (className != null ? className : "Patched_" + System.currentTimeMillis()) + ".java";
        Path patchedFile = tempDirectory.resolve(fileName);
        Files.write(patchedFile, patch.getPatchedCode().getBytes(StandardCharsets.UTF_8));

        String classpath = System.getProperty("aeg.patch.classpath");
        if (classpath == null || classpath.isEmpty()) {
            classpath = System.getProperty("java.class.path");
        }
        ProcessBuilder pb = new ProcessBuilder("javac", "-classpath", classpath, patchedFile.toString());
        Process p = pb.start();

        try {
            boolean completed = p.waitFor(30, java.util.concurrent.TimeUnit.SECONDS);
            return completed && p.exitValue() == 0;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private String extractPrimaryClassName(String code) {
        Pattern pattern = Pattern.compile("\\bpublic\\s+class\\s+(\\w+)\\b");
        Matcher matcher = pattern.matcher(code);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    private String extractPackageName(String code) {
        Pattern pattern = Pattern.compile("\\bpackage\\s+([\\w\\.]+)\\s*;");
        Matcher matcher = pattern.matcher(code);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    private String ensurePathAllowlistHelper(String code) {
        if (!code.contains("assertAllowedPath(")) {
            return code;
        }
        if (code.contains("assertAllowedPath(Object")) {
            return code;
        }
        int insertAt = code.lastIndexOf('}');
        if (insertAt <= 0) {
            return code;
        }
        String helper = "\n" +
            "    private static java.nio.file.Path assertAllowedPath(Object candidate) {\n" +
            "        java.nio.file.Path path;\n" +
            "        if (candidate instanceof java.nio.file.Path) {\n" +
            "            path = (java.nio.file.Path) candidate;\n" +
            "        } else if (candidate instanceof java.io.File) {\n" +
            "            path = ((java.io.File) candidate).toPath();\n" +
            "        } else {\n" +
            "            path = java.nio.file.Paths.get(String.valueOf(candidate));\n" +
            "        }\n" +
            "        java.nio.file.Path base = java.nio.file.Paths.get(System.getProperty(\"bean.allowed.base\", \".\"))\n" +
            "            .toAbsolutePath().normalize();\n" +
            "        java.nio.file.Path resolved = path.isAbsolute() ? path : base.resolve(path);\n" +
            "        java.nio.file.Path normalized = resolved.normalize();\n" +
            "        if (!normalized.startsWith(base)) {\n" +
            "            throw new SecurityException(\"Path traversal blocked: \" + normalized);\n" +
            "        }\n" +
            "        return normalized;\n" +
            "    }\n";
        return code.substring(0, insertAt) + helper + code.substring(insertAt);
    }

    private String ensureXPathEscapeHelper(String code) {
        if (!code.contains("escapeXPathLiteral(")) {
            return code;
        }
        if (code.contains("escapeXPathLiteral(String")) {
            return code;
        }
        int insertAt = code.lastIndexOf('}');
        if (insertAt <= 0) {
            return code;
        }
        String helper = "\n" +
            "    private static String escapeXPathLiteral(String input) {\n" +
            "        if (input == null) {\n" +
            "            return \"''\";\n" +
            "        }\n" +
            "        if (!input.contains(\"'\")) {\n" +
            "            return \"'\" + input + \"'\";\n" +
            "        }\n" +
            "        if (!input.contains(\"\\\"\")) {\n" +
            "            return \"\\\"\" + input + \"\\\"\";\n" +
            "        }\n" +
            "        String[] parts = input.split(\"'\", -1);\n" +
            "        java.util.List<String> tokens = new java.util.ArrayList<>();\n" +
            "        for (int i = 0; i < parts.length; i++) {\n" +
            "            if (!parts[i].isEmpty()) {\n" +
            "                tokens.add(\"'\" + parts[i] + \"'\");\n" +
            "            }\n" +
            "            if (i < parts.length - 1) {\n" +
            "                tokens.add(\"\\\"'\\\"\");\n" +
            "            }\n" +
            "        }\n" +
            "        if (tokens.isEmpty()) {\n" +
            "            return \"''\";\n" +
            "        }\n" +
            "        return \"concat(\" + String.join(\", \", tokens) + \")\";\n" +
            "    }\n";
        return code.substring(0, insertAt) + helper + code.substring(insertAt);
    }

    private String ensureLdapEscapeHelper(String code) {
        if (!code.contains("escapeLdapFilter(")) {
            return code;
        }
        if (code.contains("escapeLdapFilter(String")) {
            return code;
        }
        int insertAt = code.lastIndexOf('}');
        if (insertAt <= 0) {
            return code;
        }
        String helper = "\n" +
            "    private static String escapeLdapFilter(Object value) {\n" +
            "        if (value == null) {\n" +
            "            return \"\";\n" +
            "        }\n" +
            "        String input = String.valueOf(value);\n" +
            "        StringBuilder sb = new StringBuilder(input.length());\n" +
            "        for (int i = 0; i < input.length(); i++) {\n" +
            "            char c = input.charAt(i);\n" +
            "            switch (c) {\n" +
            "                case '\\\\': sb.append(\"\\\\5c\"); break;\n" +
            "                case '*': sb.append(\"\\\\2a\"); break;\n" +
            "                case '(': sb.append(\"\\\\28\"); break;\n" +
            "                case ')': sb.append(\"\\\\29\"); break;\n" +
            "                case '\\0': sb.append(\"\\\\00\"); break;\n" +
            "                default: sb.append(c);\n" +
            "            }\n" +
            "        }\n" +
            "        return sb.toString();\n" +
            "    }\n";
        return code.substring(0, insertAt) + helper + code.substring(insertAt);
    }

    private String ensureHeaderSanitizerHelper(String code) {
        if (!code.contains("sanitizeHeaderValue(") && !code.contains("sanitizeRedirectTarget(")) {
            return code;
        }
        if (code.contains("sanitizeHeaderValue(Object")) {
            return code;
        }
        int insertAt = code.lastIndexOf('}');
        if (insertAt <= 0) {
            return code;
        }
        String helper = "\n" +
            "    private static String sanitizeHeaderValue(Object value) {\n" +
            "        if (value == null) {\n" +
            "            return \"\";\n" +
            "        }\n" +
            "        String raw = String.valueOf(value);\n" +
            "        return raw.replace(\"\\r\", \"\").replace(\"\\n\", \"\");\n" +
            "    }\n" +
            "\n" +
            "    private static String sanitizeRedirectTarget(Object value) {\n" +
            "        String target = sanitizeHeaderValue(value);\n" +
            "        if (target.startsWith(\"http://\") || target.startsWith(\"https://\") || target.startsWith(\"/\")) {\n" +
            "            return target;\n" +
            "        }\n" +
            "        return \"/\";\n" +
            "    }\n";
        return code.substring(0, insertAt) + helper + code.substring(insertAt);
    }

    private String ensureElSanitizerHelper(String code) {
        if (!code.contains("sanitizeElExpression(")) {
            return code;
        }
        if (code.contains("sanitizeElExpression(Object")) {
            return code;
        }
        int insertAt = code.lastIndexOf('}');
        if (insertAt <= 0) {
            return code;
        }
        String helper = "\n" +
            "    private static String sanitizeElExpression(Object expr) {\n" +
            "        String value = String.valueOf(expr);\n" +
            "        if (!value.matches(\"\\\\$\\\\{[\\\\w\\\\s+\\\\-*/().,]*\\\\}\")) {\n" +
            "            throw new SecurityException(\"Unsafe EL expression\");\n" +
            "        }\n" +
            "        return value;\n" +
            "    }\n";
        return code.substring(0, insertAt) + helper + code.substring(insertAt);
    }

    private String ensureXxeHardeningHelper(String code) {
        if (!code.contains("secureDocumentBuilderFactory(")
            && !code.contains("secureSaxParserFactory(")
            && !code.contains("secureXmlInputFactory(")) {
            return code;
        }
        int insertAt = code.lastIndexOf('}');
        if (insertAt <= 0) {
            return code;
        }
        boolean needsDbf = code.contains("secureDocumentBuilderFactory(")
            && !code.contains("secureDocumentBuilderFactory() {");
        boolean needsSax = code.contains("secureSaxParserFactory(")
            && !code.contains("secureSaxParserFactory() {");
        boolean needsXml = code.contains("secureXmlInputFactory(")
            && !code.contains("secureXmlInputFactory() {");
        if (!needsDbf && !needsSax && !needsXml) {
            return code;
        }
        StringBuilder helper = new StringBuilder("\n");
        if (needsDbf) {
            helper.append(
                "    private static javax.xml.parsers.DocumentBuilderFactory secureDocumentBuilderFactory() {\n" +
                "        javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();\n" +
                "        try {\n" +
                "            dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n" +
                "            dbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n" +
                "            dbf.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);\n" +
                "            dbf.setXIncludeAware(false);\n" +
                "            dbf.setExpandEntityReferences(false);\n" +
                "        } catch (Exception e) {\n" +
                "            throw new RuntimeException(e);\n" +
                "        }\n" +
                "        return dbf;\n" +
                "    }\n\n"
            );
        }
        if (needsSax) {
            helper.append(
                "    private static javax.xml.parsers.SAXParserFactory secureSaxParserFactory() {\n" +
                "        javax.xml.parsers.SAXParserFactory spf = javax.xml.parsers.SAXParserFactory.newInstance();\n" +
                "        try {\n" +
                "            spf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n" +
                "            spf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n" +
                "            spf.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);\n" +
                "        } catch (Exception e) {\n" +
                "            throw new RuntimeException(e);\n" +
                "        }\n" +
                "        return spf;\n" +
                "    }\n\n"
            );
        }
        if (needsXml) {
            helper.append(
                "    private static javax.xml.stream.XMLInputFactory secureXmlInputFactory() {\n" +
                "        javax.xml.stream.XMLInputFactory xif = javax.xml.stream.XMLInputFactory.newInstance();\n" +
                "        xif.setProperty(\"javax.xml.stream.isSupportingExternalEntities\", Boolean.FALSE);\n" +
                "        xif.setProperty(\"javax.xml.stream.supportDTD\", Boolean.FALSE);\n" +
                "        return xif;\n" +
                "    }\n"
            );
        }
        return code.substring(0, insertAt) + helper + code.substring(insertAt);
    }

    private String ensureReflectionAllowlistHelper(String code) {
        if (!code.contains("assertAllowedClass(") && !code.contains("isAllowedReflectionTarget(")) {
            return code;
        }
        if (code.contains("assertAllowedClass(Object")) {
            return code;
        }
        int insertAt = code.lastIndexOf('}');
        if (insertAt <= 0) {
            return code;
        }
        String helper = "\n" +
            "    private static String assertAllowedClass(Object candidate) {\n" +
            "        String name = String.valueOf(candidate);\n" +
            "        if (!name.startsWith(\"com.beanvulnerable.\")) {\n" +
            "            throw new SecurityException(\"Invalid class: \" + name);\n" +
            "        }\n" +
            "        return name;\n" +
            "    }\n" +
            "\n" +
            "    private static boolean isAllowedReflectionTarget(java.lang.reflect.Method method) {\n" +
            "        if (method == null) {\n" +
            "            return false;\n" +
            "        }\n" +
            "        String owner = method.getDeclaringClass().getName();\n" +
            "        return owner.startsWith(\"com.beanvulnerable.\");\n" +
            "    }\n";
        return code.substring(0, insertAt) + helper + code.substring(insertAt);
    }

    private boolean layer2SemanticVerification(SecurityPatch patch) {
        String patchedCode = patch.getPatchedCode();

        boolean stillVulnerable = checkVulnerabilityPatterns(patch);
        if (stillVulnerable) {
            return false;
        }

        boolean functionalityPreserved = checkFunctionalityPreservation(patch);
        if (!functionalityPreserved) {
            return false;
        }

        if (patchedCode.contains("(Object)")) {
            return false;
        }

        return true;
    }

    private boolean checkVulnerabilityPatterns(SecurityPatch patch) {
        String vulnType = patch.getVulnerability().getVulnerabilityType();
        String patchedCode = patch.getPatchedCode();

        if ("sql_injection".equals(vulnType)) {
            boolean prepared = patchedCode.contains("PreparedStatement");
            boolean escapesQuotes = patchedCode.contains(".replace(\"'\", \"''\")");
            return !(prepared || escapesQuotes);
        }
        if ("command_injection".equals(vulnType)) {
            return !patchedCode.contains("ProcessBuilder");
        }
        if ("xpath_injection".equals(vulnType)) {
            if (patchedCode.contains("setXPathVariableResolver") ||
                patchedCode.contains("XPathVariableResolver") ||
                patchedCode.contains("escapeXPathLiteral(")) {
                return false;
            }
            return patchedCode.matches(".*XPath.*\\+.*");
        }
        if ("deserialization".equals(vulnType)) {
            return patchedCode.contains(".readObject()");
        }
        if ("path_traversal".equals(vulnType)) {
            return !(patchedCode.contains("normalize") ||
                patchedCode.contains("toRealPath") ||
                patchedCode.contains("assertAllowedPath"));
        }
        if ("reflection".equals(vulnType) || "reflection_injection".equals(vulnType)) {
            return !patchedCode.contains("startsWith(\"com.beanvulnerable.\")");
        }
        return false;
    }

    private boolean checkFunctionalityPreservation(SecurityPatch patch) {
        String patchedCode = patch.getPatchedCode();
        if (patchedCode.contains("assertAllowedPath(") ||
            patchedCode.contains("escapeXPathLiteral(") ||
            patchedCode.contains("XPathVariableResolver") ||
            patchedCode.contains("escapeLdapFilter(") ||
            patchedCode.contains("sanitizeHeaderValue(") ||
            patchedCode.contains("sanitizeRedirectTarget(") ||
            patchedCode.contains("sanitizeElExpression(") ||
            patchedCode.contains("secureDocumentBuilderFactory(") ||
            patchedCode.contains("secureSaxParserFactory(") ||
            patchedCode.contains("secureXmlInputFactory(") ||
            patchedCode.contains("assertAllowedClass(") ||
            patchedCode.contains("isAllowedReflectionTarget(")) {
            return true;
        }
        int vulnLen = patch.getVulnerableCode().length();
        int patchLen = patch.getPatchedCode().length();

        return Math.abs(vulnLen - patchLen) < vulnLen / 2;
    }

    private boolean matchesSinkHint(Vulnerability vulnerability, PatchTemplate template) {
        if (vulnerability == null || template == null) {
            return true;
        }
        String id = vulnerability.getId();
        if (id == null || !id.contains("->") || !id.contains(":")) {
            return true;
        }
        int arrow = id.indexOf("->");
        int colon = id.lastIndexOf(":");
        if (arrow < 0 || colon < 0 || colon <= arrow + 2) {
            return true;
        }
        String sinkId = id.substring(arrow + 2, colon);
        String sinkClass = sinkId;
        String sinkMethod = "";
        int hashIdx = sinkId.indexOf('#');
        if (hashIdx > 0) {
            sinkClass = sinkId.substring(0, hashIdx);
            sinkMethod = sinkId.substring(hashIdx + 1);
        }
        String simpleName = sinkClass;
        int slashIdx = simpleName.lastIndexOf('/');
        int dotIdx = simpleName.lastIndexOf('.');
        int cut = Math.max(slashIdx, dotIdx);
        if (cut >= 0) {
            simpleName = simpleName.substring(cut + 1);
        }
        String pattern = template.getVulnerablePattern();
        if (simpleName.contains("FileInputStream") && !pattern.contains("FileInputStream")) {
            return false;
        }
        if (simpleName.contains("FileOutputStream") && !pattern.contains("FileOutputStream")) {
            return false;
        }
        if (simpleName.contains("FileReader") && !pattern.contains("FileReader")) {
            return false;
        }
        if (simpleName.contains("FileWriter") && !pattern.contains("FileWriter")) {
            return false;
        }
        if (simpleName.equals("Files") && !sinkMethod.isEmpty()) {
            if (!pattern.contains("Files") && !pattern.contains(sinkMethod)) {
                return false;
            }
        }
        if ((simpleName.endsWith("PrintWriter")
            || simpleName.endsWith("JspWriter")
            || simpleName.endsWith("ServletOutputStream"))
            && !sinkMethod.isEmpty()) {
            if (!pattern.contains(sinkMethod)) {
                return false;
            }
        }
        return true;
    }

    private boolean layer3ExecutionVerification(SecurityPatch patch) throws Exception {
        String className = extractPrimaryClassName(patch.getPatchedCode());
        if (className == null) {
            return true;
        }
        String packageName = extractPackageName(patch.getPatchedCode());
        String fqn = packageName == null ? className : packageName + "." + className;

        Path execDir = Files.createTempDirectory(tempDirectory, "patch_exec_");
        Path sourceFile = execDir.resolve(className + ".java");
        Files.write(sourceFile, patch.getPatchedCode().getBytes(StandardCharsets.UTF_8));

        String classpath = System.getProperty("aeg.patch.classpath");
        if (classpath == null || classpath.isEmpty()) {
            classpath = System.getProperty("java.class.path");
        }

        ProcessBuilder compile = new ProcessBuilder(
            "javac",
            "-classpath",
            classpath,
            "-d",
            execDir.toString(),
            sourceFile.toString()
        );
        Process compileProcess = compile.start();
        boolean compiled = compileProcess.waitFor(30, java.util.concurrent.TimeUnit.SECONDS);
        if (!compiled || compileProcess.exitValue() != 0) {
            return false;
        }

        String harness = String.join("\n",
            "import java.lang.reflect.Method;",
            "import java.lang.reflect.Modifier;",
            "public class PatchSmokeTest {",
            "  private static Boolean invokeIfPresent(Class<?> target, String methodName, String[] smokeArgs) {",
            "    Method method = null;",
            "    try { method = target.getDeclaredMethod(methodName); } catch (NoSuchMethodException ignored) {}",
            "    if (method == null) {",
            "      try { method = target.getDeclaredMethod(methodName, String.class); } catch (NoSuchMethodException ignored) {}",
            "    }",
            "    if (method == null) {",
            "      try { method = target.getDeclaredMethod(methodName, String[].class); } catch (NoSuchMethodException ignored) {}",
            "    }",
            "    if (method == null) {",
            "      try { method = target.getMethod(methodName); } catch (NoSuchMethodException ignored) {}",
            "    }",
            "    if (method == null) {",
            "      try { method = target.getMethod(methodName, String.class); } catch (NoSuchMethodException ignored) {}",
            "    }",
            "    if (method == null) {",
            "      try { method = target.getMethod(methodName, String[].class); } catch (NoSuchMethodException ignored) {}",
            "    }",
            "    if (method == null) { return null; }",
            "    try {",
            "      method.setAccessible(true);",
            "      Object instance = null;",
            "      if (!Modifier.isStatic(method.getModifiers())) {",
            "        instance = target.getDeclaredConstructor().newInstance();",
            "      }",
            "      Object result;",
            "      if (method.getParameterCount() == 0) {",
            "        result = method.invoke(instance);",
            "      } else if (method.getParameterCount() == 1 && method.getParameterTypes()[0].equals(String.class)) {",
            "        String arg = smokeArgs.length > 0 ? smokeArgs[0] : \"\";",
            "        result = method.invoke(instance, arg);",
            "      } else if (method.getParameterCount() == 1 && method.getParameterTypes()[0].equals(String[].class)) {",
            "        result = method.invoke(instance, (Object) smokeArgs);",
            "      } else {",
            "        return Boolean.FALSE;",
            "      }",
            "      if (method.getReturnType().equals(boolean.class) || method.getReturnType().equals(Boolean.class)) {",
            "        return Boolean.TRUE.equals(result);",
            "      }",
            "      return Boolean.TRUE;",
            "    } catch (Throwable t) {",
            "      return Boolean.FALSE;",
            "    }",
            "  }",
            "  public static void main(String[] args) throws Exception {",
            "    if (args.length == 0) { System.exit(2); }",
            "    ClassLoader loader = Thread.currentThread().getContextClassLoader();",
            "    Class<?> target = Class.forName(args[0], false, loader);",
            "    String methodName = System.getProperty(\"aeg.patch.smokeMethod\", \"\").trim();",
            "    String argSpec = System.getProperty(\"aeg.patch.smokeArgs\", \"\").trim();",
            "    boolean requireSmoke = Boolean.parseBoolean(System.getProperty(\"aeg.patch.requireSmoke\", \"false\"));",
            "    String[] smokeArgs = argSpec.isEmpty() ? new String[0] : argSpec.split(\"\\\\s*,\\\\s*\");",
            "    if (!methodName.isEmpty()) {",
            "      Boolean outcome = invokeIfPresent(target, methodName, smokeArgs);",
            "      System.exit(Boolean.TRUE.equals(outcome) ? 0 : 4);",
            "    }",
            "    String[] candidates = new String[]{\"selfTest\",\"smokeTest\",\"test\",\"runSmoke\",\"validate\"};",
            "    for (String candidate : candidates) {",
            "      Boolean outcome = invokeIfPresent(target, candidate, smokeArgs);",
            "      if (outcome == null) {",
            "        continue;",
            "      }",
            "      System.exit(Boolean.TRUE.equals(outcome) ? 0 : 4);",
            "    }",
            "    if (requireSmoke) { System.exit(5); }",
            "  }",
            "}"
        );
        Path harnessFile = execDir.resolve("PatchSmokeTest.java");
        Files.write(harnessFile, harness.getBytes(StandardCharsets.UTF_8));
        String runtimeClasspath = execDir.toString() + java.io.File.pathSeparator + classpath;
        ProcessBuilder compileHarness = new ProcessBuilder(
            "javac",
            "-classpath",
            runtimeClasspath,
            "-d",
            execDir.toString(),
            harnessFile.toString()
        );
        Process harnessProcess = compileHarness.start();
        boolean harnessCompiled = harnessProcess.waitFor(30, java.util.concurrent.TimeUnit.SECONDS);
        if (!harnessCompiled || harnessProcess.exitValue() != 0) {
            return false;
        }

        ProcessBuilder runHarness = new ProcessBuilder(
            "java",
            "-classpath",
            runtimeClasspath,
            "PatchSmokeTest",
            fqn
        );
        Process runProcess = runHarness.start();
        boolean completed = runProcess.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
        if (!completed) {
            runProcess.destroy();
            return false;
        }
        return runProcess.exitValue() == 0;
    }

    public PatchReport generatePatchReport(SecurityPatch patch) {
        PatchReport report = new PatchReport(patch);

        report.setVulnerabilityType(patch.getVulnerability().getVulnerabilityType());
        report.setSeverity(calculatePatchSeverity(patch));
        report.setConfidence(calculatePatchConfidence(patch));

        report.setVulnerableCode(patch.getVulnerableCode());
        report.setPatchedCode(patch.getPatchedCode());

        report.setExplanation(generateExplanation(patch));
        report.setBestPractices(generateBestPractices(patch));

        report.setVerificationStatus(patch.getVerificationStatus());
        report.setLayer1Verified(patch.isLayer1Verified());
        report.setLayer2Verified(patch.isLayer2Verified());
        report.setLayer3Verified(patch.isLayer3Verified());

        return report;
    }

    private String calculatePatchSeverity(SecurityPatch patch) {
        return patch.getVulnerability().getVulnerabilityType();
    }

    private double calculatePatchConfidence(SecurityPatch patch) {
        double confidence = 0.0;

        if (patch.isLayer1Verified()) {
            confidence += 0.33;
        }
        if (patch.isLayer2Verified()) {
            confidence += 0.33;
        }
        if (patch.isLayer3Verified()) {
            confidence += 0.34;
        }

        return confidence;
    }

    private String generateExplanation(SecurityPatch patch) {
        return "Patch fixes " + patch.getVulnerability().getVulnerabilityType() +
            " by " + patch.getSynthesisMethod();
    }

    private String generateBestPractices(SecurityPatch patch) {
        return "See OWASP guidelines for " +
            patch.getVulnerability().getVulnerabilityType();
    }

    public List<SecurityPatch> generatePatches(
        List<Vulnerability> vulnerabilities,
        Map<String, String> vulnerableCodes) throws Exception {

        List<SecurityPatch> patches = new ArrayList<>();

        for (Vulnerability vuln : vulnerabilities) {
            String vulnCode = vulnerableCodes.get(vuln.getId());
            if (vulnCode == null) {
                continue;
            }

            SecurityPatch patch = generatePatchFromTemplate(vuln, vulnCode);

            if (patch == null || !patch.isLayer1Verified()) {
                try {
                    patch = generatePatchFromLLM(vuln, vulnCode, null);
                } catch (Exception e) {
                    System.err.println("LLM patch generation failed: " + e);
                }
            }

            if (patch != null && patch.isLayer1Verified()) {
                patches.add(patch);
            }
        }

        return patches;
    }
}
