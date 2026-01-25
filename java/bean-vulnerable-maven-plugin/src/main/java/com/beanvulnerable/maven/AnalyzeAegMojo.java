package com.beanvulnerable.maven;

import com.beanvulnerable.aeg.BytecodeAnalyzer;
import com.beanvulnerable.aeg.HeuristicVulnerabilityDetector;
import com.beanvulnerable.aeg.domain.ClassAnalysis;
import com.beanvulnerable.aeg.domain.Vulnerability;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Mojo(name = "analyze-aeg", defaultPhase = LifecyclePhase.VERIFY)
public class AnalyzeAegMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project}", required = true, readonly = true)
    private MavenProject project;

    @Parameter(defaultValue = "${project.build.directory}", required = true)
    private File buildDirectory;

    @Parameter(defaultValue = "100")
    private int pathDepth;

    @Parameter(defaultValue = "30000")
    private long timeoutMs;

    @Parameter(defaultValue = "HIGH,CRITICAL")
    private String severity;

    @Parameter(defaultValue = "true")
    private boolean generatePocs;

    @Parameter(defaultValue = "true")
    private boolean generatePatches;

    @Parameter(defaultValue = "json,html")
    private String reportFormat;

    @Override
    public void execute() throws MojoExecutionException {
        getLog().info("Bean-Vulnerable AEG Analysis starting...");

        try {
            Path classesDir = Paths.get(buildDirectory.getAbsolutePath(), "classes");
            if (!Files.exists(classesDir)) {
                getLog().warn("Classes directory not found: " + classesDir);
                return;
            }

            BytecodeAnalyzer bytecodeAnalyzer = new BytecodeAnalyzer();
            HeuristicVulnerabilityDetector heuristicDetector = new HeuristicVulnerabilityDetector();

            List<Vulnerability> vulnerabilities = new ArrayList<>();
            Map<String, String> vulnerabilitySources = new HashMap<>();

            Files.walk(classesDir)
                .filter(p -> p.toString().endsWith(".class"))
                .forEach(classFile -> {
                    try {
                        getLog().debug("Analyzing: " + classFile);
                        ClassAnalysis classAnalysis =
                            bytecodeAnalyzer.analyzeClass(classFile.toString());
                        String sourceContent = resolveSourceForClass(classAnalysis.getClassName());
                        if (sourceContent == null) {
                            sourceContent = resolveSourceFromClassFile(classFile);
                        }
                        List<Vulnerability> classVulns = trySymbolicAnalysis(classAnalysis);
                        if (classVulns.isEmpty()) {
                            classVulns = heuristicDetector.detect(classAnalysis);
                        }
                        vulnerabilities.addAll(classVulns);
                        if (sourceContent != null) {
                            for (Vulnerability vuln : classVulns) {
                                vulnerabilitySources.put(vuln.getId(), sourceContent);
                            }
                        }
                    } catch (Exception e) {
                        getLog().warn("Analysis failed for " + classFile, e);
                    }
                });

            getLog().info("Found " + vulnerabilities.size() + " vulnerabilities");

            List<Object> pocs = new ArrayList<>();
            if (generatePocs) {
                getLog().info("Generating PoCs...");
                pocs = tryGeneratePoCs(vulnerabilities);
                getLog().info("Generated " + pocs.size() + " PoCs");
            }

            List<Object> patches = new ArrayList<>();
            if (generatePatches) {
                getLog().info("Generating patches...");
                String patchClasspath = buildPatchClasspath();
                if (!patchClasspath.isEmpty()) {
                    System.setProperty("aeg.patch.classpath", patchClasspath);
                }
                patches = tryGeneratePatches(vulnerabilities, vulnerabilitySources);
                System.clearProperty("aeg.patch.classpath");
                getLog().info("Generated " + patches.size() + " patches");
            }

            getLog().info("Source map entries: " + vulnerabilitySources.size());
            generateReports(vulnerabilities, pocs, patches, vulnerabilitySources.size());

            getLog().info("Analysis complete");

        } catch (Exception e) {
            throw new MojoExecutionException("Analysis failed", e);
        }
    }

    private void generateReports(List<Vulnerability> vulnerabilities,
                                 List<Object> pocs,
                                 List<Object> patches,
                                 int sourceMapEntries) throws IOException {

        Path reportDir = Paths.get(buildDirectory.getAbsolutePath(), "bean-reports");
        Files.createDirectories(reportDir);

        if (reportFormat.contains("json")) {
            generateJsonReport(vulnerabilities, pocs, patches, reportDir, sourceMapEntries);
        }

        if (reportFormat.contains("html")) {
            generateHtmlReport(vulnerabilities, pocs, patches, reportDir, sourceMapEntries);
        }
    }

    private void generateJsonReport(List<Vulnerability> vulnerabilities,
                                    List<Object> pocs,
                                    List<Object> patches,
                                    Path reportDir,
                                    int sourceMapEntries) throws IOException {
        String payload = buildJsonReport(vulnerabilities, pocs, patches, sourceMapEntries);
        Files.write(reportDir.resolve("summary.json"), payload.getBytes(StandardCharsets.UTF_8));
    }

    private void generateHtmlReport(List<Vulnerability> vulnerabilities,
                                    List<Object> pocs,
                                    List<Object> patches,
                                    Path reportDir,
                                    int sourceMapEntries) throws IOException {
        String html = buildHtmlReport(vulnerabilities, pocs, patches, sourceMapEntries);
        Files.write(reportDir.resolve("summary.html"), html.getBytes(StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    private List<Vulnerability> trySymbolicAnalysis(ClassAnalysis analysis) {
        try {
            Class<?> executorClass = Class.forName("com.beanvulnerable.aeg.SymbolicExecutor");
            Object executor = executorClass.getConstructor().newInstance();
            Object result = executorClass.getMethod("analyzeClass", ClassAnalysis.class).invoke(executor, analysis);
            Object vulns = result.getClass().getMethod("getVulnerabilities").invoke(result);
            if (vulns instanceof List) {
                return (List<Vulnerability>) vulns;
            }
        } catch (Exception ignored) {
        }
        return new ArrayList<>();
    }

    private List<Object> tryGeneratePoCs(List<Vulnerability> vulnerabilities) {
        try {
            Class<?> synthClass = Class.forName("com.beanvulnerable.aeg.PoCSynthesizer");
            Object synthesizer = synthClass.getConstructor().newInstance();
            Object pocs = synthClass.getMethod("generatePoCsForVulnerabilities", List.class)
                .invoke(synthesizer, vulnerabilities);
            if (pocs instanceof List) {
                return (List<Object>) pocs;
            }
        } catch (Exception e) {
            getLog().warn("PoC synthesis unavailable: " + e.getMessage());
        }
        return new ArrayList<>();
    }

    private List<Object> tryGeneratePatches(List<Vulnerability> vulnerabilities) {
        return tryGeneratePatches(vulnerabilities, new HashMap<String, String>());
    }

    private List<Object> tryGeneratePatches(List<Vulnerability> vulnerabilities,
                                            Map<String, String> vulnerableCodeMap) {
        try {
            Class<?> synthClass = Class.forName("com.beanvulnerable.aeg.PatchSynthesizer");
            Object synthesizer = synthClass.getConstructor().newInstance();
            Object patches = synthClass.getMethod("generatePatches", List.class, Map.class)
                .invoke(synthesizer, vulnerabilities, vulnerableCodeMap);
            if (patches instanceof List) {
                return (List<Object>) patches;
            }
        } catch (Exception e) {
            getLog().warn("Patch synthesis unavailable: " + e.getMessage());
        }
        return new ArrayList<>();
    }

    private String buildJsonReport(List<Vulnerability> vulnerabilities,
                                   List<Object> pocs,
                                   List<Object> patches,
                                   int sourceMapEntries) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"totalVulnerabilities\": ").append(vulnerabilities.size()).append(",\n");
        sb.append("  \"pocCount\": ").append(pocs.size()).append(",\n");
        sb.append("  \"patchCount\": ").append(patches.size()).append(",\n");
        sb.append("  \"sourceMapEntries\": ").append(sourceMapEntries).append(",\n");
        sb.append("  \"vulnerabilities\": [\n");
        for (int i = 0; i < vulnerabilities.size(); i++) {
            Vulnerability vuln = vulnerabilities.get(i);
            sb.append("    {");
            sb.append("\"id\":\"").append(escape(vuln.getId())).append("\",");
            sb.append("\"type\":\"").append(escape(vuln.getVulnerabilityType())).append("\",");
            sb.append("\"sinkType\":\"").append(escape(vuln.getSinkType())).append("\",");
            sb.append("\"description\":\"").append(escape(vuln.getDescription())).append("\"");
            sb.append("}");
            if (i < vulnerabilities.size() - 1) {
                sb.append(",");
            }
            sb.append("\n");
        }
        sb.append("  ],\n");
        sb.append("  \"pocs\": [\n");
        for (int i = 0; i < pocs.size(); i++) {
            Object poc = pocs.get(i);
            String pocId = extractString(poc, "getPocId");
            String vulnType = extractString(poc, "getVulnerabilityType");
            String status = extractString(poc, "getVerificationStatus");
            String code = extractString(poc, "getPocCode");
            sb.append("    {");
            sb.append("\"id\":\"").append(escape(pocId)).append("\",");
            sb.append("\"type\":\"").append(escape(vulnType)).append("\",");
            sb.append("\"status\":\"").append(escape(status)).append("\",");
            sb.append("\"code_preview\":\"").append(escape(truncate(code, 800))).append("\",");
            sb.append("\"code_length\":").append(code != null ? code.length() : 0);
            sb.append("}");
            if (i < pocs.size() - 1) {
                sb.append(",");
            }
            sb.append("\n");
        }
        sb.append("  ],\n");
        sb.append("  \"patches\": [\n");
        for (int i = 0; i < patches.size(); i++) {
            Object patch = patches.get(i);
            String templateId = extractString(patch, "getTemplateId");
            String status = extractString(patch, "getVerificationStatus");
            String patchedCode = extractString(patch, "getPatchedCode");
            String vulnId = extractNestedString(patch, "getVulnerability", "getId");
            String vulnType = extractNestedString(patch, "getVulnerability", "getVulnerabilityType");
            sb.append("    {");
            sb.append("\"vulnerability_id\":\"").append(escape(vulnId)).append("\",");
            sb.append("\"type\":\"").append(escape(vulnType)).append("\",");
            sb.append("\"template_id\":\"").append(escape(templateId)).append("\",");
            sb.append("\"status\":\"").append(escape(status)).append("\",");
            sb.append("\"patched_preview\":\"").append(escape(truncate(patchedCode, 800))).append("\",");
            sb.append("\"patched_length\":").append(patchedCode != null ? patchedCode.length() : 0);
            sb.append("}");
            if (i < patches.size() - 1) {
                sb.append(",");
            }
            sb.append("\n");
        }
        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    private String buildHtmlReport(List<Vulnerability> vulnerabilities,
                                   List<Object> pocs,
                                   List<Object> patches,
                                   int sourceMapEntries) {
        StringBuilder sb = new StringBuilder();
        sb.append("<html><head><title>Bean-Vulnerable Report</title></head><body>");
        sb.append("<h1>Bean-Vulnerable AEG Report</h1>");
        sb.append("<p>Vulnerabilities found: ").append(vulnerabilities.size()).append("</p>");
        sb.append("<p>Source map entries: ").append(sourceMapEntries).append("</p>");
        if (!vulnerabilities.isEmpty()) {
            sb.append("<table border=\"1\" cellspacing=\"0\" cellpadding=\"4\">");
            sb.append("<tr><th>ID</th><th>Type</th><th>Sink</th><th>Description</th></tr>");
            for (Vulnerability vuln : vulnerabilities) {
                sb.append("<tr>");
                sb.append("<td>").append(escapeHtml(vuln.getId())).append("</td>");
                sb.append("<td>").append(escapeHtml(vuln.getVulnerabilityType())).append("</td>");
                sb.append("<td>").append(escapeHtml(vuln.getSinkType())).append("</td>");
                sb.append("<td>").append(escapeHtml(vuln.getDescription())).append("</td>");
                sb.append("</tr>");
            }
            sb.append("</table>");
        }
        if (!pocs.isEmpty()) {
            sb.append("<h2>PoCs</h2>");
            for (Object poc : pocs) {
                String pocId = extractString(poc, "getPocId");
                String vulnType = extractString(poc, "getVulnerabilityType");
                String status = extractString(poc, "getVerificationStatus");
                String code = extractString(poc, "getPocCode");
                sb.append("<details><summary>")
                    .append(escapeHtml(pocId))
                    .append(" (").append(escapeHtml(vulnType)).append(") - ")
                    .append(escapeHtml(status))
                    .append("</summary>");
                sb.append("<pre>").append(escapeHtml(truncate(code, 2000))).append("</pre>");
                sb.append("</details>");
            }
        }
        if (!patches.isEmpty()) {
            sb.append("<h2>Patches</h2>");
            for (Object patch : patches) {
                String templateId = extractString(patch, "getTemplateId");
                String status = extractString(patch, "getVerificationStatus");
                String vulnId = extractNestedString(patch, "getVulnerability", "getId");
                String vulnType = extractNestedString(patch, "getVulnerability", "getVulnerabilityType");
                String code = extractString(patch, "getPatchedCode");
                sb.append("<details><summary>")
                    .append(escapeHtml(vulnId))
                    .append(" (").append(escapeHtml(vulnType)).append(") - ")
                    .append(escapeHtml(status))
                    .append(" [").append(escapeHtml(templateId)).append("]")
                    .append("</summary>");
                sb.append("<pre>").append(escapeHtml(truncate(code, 2000))).append("</pre>");
                sb.append("</details>");
            }
        }
        sb.append("</body></html>");
        return sb.toString();
    }

    private String escape(String input) {
        if (input == null) {
            return "";
        }
        return input.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r");
    }

    private String escapeHtml(String input) {
        if (input == null) {
            return "";
        }
        return input.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;");
    }

    private String truncate(String input, int max) {
        if (input == null) {
            return "";
        }
        if (input.length() <= max) {
            return input;
        }
        return input.substring(0, max) + "...";
    }

    private String extractString(Object obj, String methodName) {
        if (obj == null) {
            return "";
        }
        try {
            Object value = obj.getClass().getMethod(methodName).invoke(obj);
            return value != null ? String.valueOf(value) : "";
        } catch (Exception ignored) {
            return "";
        }
    }

    private String extractNestedString(Object obj, String methodName, String nestedMethod) {
        if (obj == null) {
            return "";
        }
        try {
            Object nested = obj.getClass().getMethod(methodName).invoke(obj);
            if (nested == null) {
                return "";
            }
            Object value = nested.getClass().getMethod(nestedMethod).invoke(nested);
            return value != null ? String.valueOf(value) : "";
        } catch (Exception ignored) {
            return "";
        }
    }

    private String resolveSourceForClass(String className) {
        if (className == null || className.isEmpty() || project == null) {
            return null;
        }
        String normalized = className.replace('.', '/');
        int innerIdx = normalized.indexOf('$');
        if (innerIdx != -1) {
            normalized = normalized.substring(0, innerIdx);
        }
        if (!normalized.endsWith(".java")) {
            normalized = normalized + ".java";
        }
        for (Object rootObj : project.getCompileSourceRoots()) {
            if (!(rootObj instanceof String)) {
                continue;
            }
            Path candidate = Paths.get((String) rootObj, normalized);
            if (Files.exists(candidate)) {
                try {
                    return Files.readString(candidate, StandardCharsets.UTF_8);
                } catch (IOException ignored) {
                    return null;
                }
            }
        }
        if (project.getBasedir() != null) {
            Path root = project.getBasedir().toPath().resolve("src/main/java");
            Path candidate = root.resolve(normalized);
            if (Files.exists(candidate)) {
                try {
                    return Files.readString(candidate, StandardCharsets.UTF_8);
                } catch (IOException ignored) {
                    return null;
                }
            }
        }
        return null;
    }

    private String resolveSourceFromClassFile(Path classFile) {
        if (classFile == null || project == null || project.getBasedir() == null) {
            return null;
        }
        Path baseDir = project.getBasedir().toPath();
        Path targetRoot = baseDir.resolve("target/classes");
        if (!classFile.startsWith(targetRoot)) {
            return null;
        }
        Path relative = targetRoot.relativize(classFile);
        String relativePath = relative.toString().replace(".class", ".java");
        Path sourceCandidate = baseDir.resolve("src/main/java").resolve(relativePath);
        if (!Files.exists(sourceCandidate)) {
            return null;
        }
        try {
            return Files.readString(sourceCandidate, StandardCharsets.UTF_8);
        } catch (IOException ignored) {
            return null;
        }
    }

    private String buildPatchClasspath() {
        if (project == null) {
            return "";
        }
        List<String> elements = new ArrayList<>();
        try {
            elements.addAll(project.getCompileClasspathElements());
        } catch (Exception e) {
            getLog().warn("Failed to resolve compile classpath: " + e.getMessage());
        }
        if (buildDirectory != null) {
            Path classesDir = Paths.get(buildDirectory.getAbsolutePath(), "classes");
            if (Files.exists(classesDir)) {
                elements.add(classesDir.toString());
            }
        }
        if (elements.isEmpty()) {
            return "";
        }
        return String.join(File.pathSeparator, elements);
    }
}
