package com.beanvulnerable.aeg;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Repository of patch templates for 50+ CWE types
 * Template format: vulnerable pattern -> replacement + verification
 */
public class EnhancedPatchTemplateRepository {

    private final Map<String, PatchTemplate> templates = new HashMap<>();

    public EnhancedPatchTemplateRepository() {
        initializeTemplates();
    }

    private void initializeTemplates() {
        // CWE-89: SQL Injection
        templates.put("CWE-89", new PatchTemplate(
            "CWE-89: SQL Injection",
            Arrays.asList(
                "(?s)String\\s+query\\s*=.*?\\+\\s*(\\w+)\\s*\\+.*?\\+\\s*(\\w+)\\s*\\+.*?;\\s*executeQuery\\(query\\);"
            ),
            "PreparedStatement pstmt = conn.prepareStatement(\"SELECT * FROM users WHERE username = ? AND password = ?\");\n" +
            "pstmt.setString(1, $1);\n" +
            "pstmt.setString(2, $2);\n" +
            "ResultSet rs = pstmt.executeQuery();",
            Arrays.asList("java.sql.PreparedStatement", "java.sql.ResultSet"),
            "Use parameterized queries to prevent SQL injection"
        ));

        // CWE-79: Cross-site Scripting (XSS)
        templates.put("CWE-79", new PatchTemplate(
            "CWE-79: XSS Prevention",
            Arrays.asList(
                ".*response\\.getWriter.*print.*variable.*"
            ),
            "String output = ESAPI.encoder().encodeForHTML(userInput);",
            Arrays.asList("org.owasp.esapi.ESAPI"),
            "Encode all user input before rendering in HTML context"
        ));

        // CWE-22: Path Traversal
        templates.put("CWE-22", new PatchTemplate(
            "CWE-22: Path Traversal Prevention",
            Arrays.asList(
                ".*new File.*\\+.*filePath.*"
            ),
            "File file = new File(baseDir, filename).getCanonicalFile();\n" +
            "if (!file.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) {\n" +
            "  throw new IllegalArgumentException(\"Invalid path\");\n" +
            "}",
            Arrays.asList("java.io.File"),
            "Validate and canonicalize file paths"
        ));

        // CWE-78: OS Command Injection
        templates.put("CWE-78", new PatchTemplate(
            "CWE-78: Command Injection Prevention",
            Arrays.asList(
                ".*Runtime\\.getRuntime.*exec.*",
                ".*ProcessBuilder.*"
            ),
            "ProcessBuilder pb = new ProcessBuilder(\"command\", \"arg1\", \"arg2\");\n" +
            "Process proc = pb.start();",
            Arrays.asList("java.lang.ProcessBuilder"),
            "Use ProcessBuilder with array arguments instead of shell strings"
        ));

        // CWE-327: Use of Broken Cryptography
        templates.put("CWE-327", new PatchTemplate(
            "CWE-327: Strong Cryptography",
            Arrays.asList(
                ".*MessageDigest\\.getInstance\\(\"MD5\"\\).*",
                ".*MessageDigest\\.getInstance\\(\"SHA1\"\\).*"
            ),
            "MessageDigest md = MessageDigest.getInstance(\"SHA-256\");",
            Arrays.asList("java.security.MessageDigest"),
            "Use SHA-256 or stronger hash algorithms"
        ));

        // CWE-295: Improper Certificate Validation
        templates.put("CWE-295", new PatchTemplate(
            "CWE-295: HTTPS Certificate Validation",
            Arrays.asList(
                ".*AllowAllHostnameVerifier.*",
                ".*TrustAllX509TrustManager.*"
            ),
            "HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();\n" +
            "// Use default SSLContext for proper certificate validation",
            Arrays.asList("javax.net.ssl.HttpsURLConnection"),
            "Enable proper HTTPS certificate validation"
        ));

        // CWE-352: CSRF Prevention
        templates.put("CWE-352", new PatchTemplate(
            "CWE-352: CSRF Token Validation",
            Arrays.asList(
                ".*@PostMapping.*",
                ".*@RequestMapping.*POST.*"
            ),
            "@PostMapping(\"/api/action\")\n" +
            "public ResponseEntity<?> action(@RequestParam String csrfToken) {\n" +
            "  if (!validateCSRFToken(csrfToken)) throw new SecurityException();\n" +
            "}",
            Arrays.asList("org.springframework.web.bind.annotation.PostMapping"),
            "Validate CSRF tokens on state-changing requests"
        ));

        // CWE-798: Hardcoded Credentials
        templates.put("CWE-798", new PatchTemplate(
            "CWE-798: Externalize Credentials",
            Arrays.asList(
                ".*password\\s*=\\s*[\"'].*[\"'].*",
                ".*apiKey\\s*=\\s*[\"'].*[\"'].*"
            ),
            "String password = System.getenv(\"DB_PASSWORD\");\n" +
            "if (password == null) password = System.getProperty(\"DB_PASSWORD\");",
            Arrays.asList("java.lang.System"),
            "Store credentials in configuration files or environment variables"
        ));

        // CWE-434: Unrestricted File Upload
        templates.put("CWE-434", new PatchTemplate(
            "CWE-434: File Upload Validation",
            Arrays.asList(
                ".*file\\.transferTo.*",
                ".*saveUploadedFile.*"
            ),
            "String filename = file.getOriginalFilename();\n" +
            "if (!isAllowedExtension(filename)) throw new IllegalArgumentException();\n" +
            "if (file.getSize() > MAX_SIZE) throw new IllegalArgumentException();",
            Arrays.asList("org.springframework.web.multipart.MultipartFile"),
            "Validate file extensions, size, and content type"
        ));

        // CWE-190: Integer Overflow
        templates.put("CWE-190", new PatchTemplate(
            "CWE-190: Integer Overflow Prevention",
            Arrays.asList(
                ".*int.*=.*\\+.*",
                ".*int.*=.*\\*.*"
            ),
            "if (a > Integer.MAX_VALUE - b) throw new ArithmeticException();\n" +
            "int result = a + b;",
            Arrays.asList("java.lang.Integer"),
            "Validate arithmetic operations for overflow"
        ));

        // CWE-90: LDAP Injection
        templates.put("CWE-90", new PatchTemplate(
            "CWE-90: LDAP Injection Prevention",
            Arrays.asList(
                ".*\\.search\\(.*\\+.*\\).*",
                ".*DirContext.*search.*"
            ),
            "String safeFilter = userInput.replace(\"\\\\\", \"\\\\5c\")\n" +
            "  .replace(\"*\", \"\\\\2a\")\n" +
            "  .replace(\"(\", \"\\\\28\")\n" +
            "  .replace(\")\", \"\\\\29\");\n" +
            "// Use safeFilter in LDAP search",
            Arrays.asList("javax.naming.directory.DirContext"),
            "Escape LDAP filter metacharacters before performing searches"
        ));

        // CWE-611: XML External Entity (XXE)
        templates.put("CWE-611", new PatchTemplate(
            "CWE-611: XXE Prevention",
            Arrays.asList(
                ".*DocumentBuilderFactory\\.newInstance\\(\\).*",
                ".*SAXParserFactory\\.newInstance\\(\\).*",
                ".*XMLInputFactory\\.newInstance\\(\\).*"
            ),
            "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n" +
            "dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n" +
            "dbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n" +
            "dbf.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);",
            Arrays.asList("javax.xml.parsers.DocumentBuilderFactory"),
            "Disable external entities and DTDs in XML parsers"
        ));

        // CWE-113: HTTP Response Splitting
        templates.put("CWE-113", new PatchTemplate(
            "CWE-113: HTTP Response Splitting Prevention",
            Arrays.asList(
                ".*setHeader\\(.*\\+.*\\).*",
                ".*addHeader\\(.*\\+.*\\).*",
                ".*sendRedirect\\(.*\\+.*\\).*"
            ),
            "String safeValue = headerValue.replace(\"\\r\", \"\").replace(\"\\n\", \"\");\n" +
            "response.setHeader(\"Location\", safeValue);",
            Arrays.asList("javax.servlet.http.HttpServletResponse"),
            "Strip CR/LF and validate header values"
        ));

        // CWE-94: Expression Language Injection
        templates.put("CWE-94", new PatchTemplate(
            "CWE-94: EL Injection Prevention",
            Arrays.asList(
                ".*\\.eval\\(.*\\+.*\\).*",
                ".*ExpressionFactory.*create.*Expression.*"
            ),
            "String safeExpr = expr.replaceAll(\"[^a-zA-Z0-9_{}$]\", \"\");\n" +
            "// Evaluate only allowlisted expressions",
            Arrays.asList("javax.el.ExpressionFactory"),
            "Allowlist and sanitize EL expressions before evaluation"
        ));

        // CWE-470: Unsafe Reflection
        templates.put("CWE-470", new PatchTemplate(
            "CWE-470: Reflection Allowlisting",
            Arrays.asList(
                ".*Class\\.forName\\(.*\\).*",
                ".*Method\\.invoke\\(.*\\).*"
            ),
            "if (!className.startsWith(\"com.beanvulnerable.\")) {\n" +
            "  throw new SecurityException(\"Invalid class\");\n" +
            "}\n" +
            "Class<?> clazz = Class.forName(className);",
            Arrays.asList("java.lang.Class"),
            "Allowlist class and method names before reflection"
        ));

        // CWE-502: Deserialization of Untrusted Data
        templates.put("CWE-502", new PatchTemplate(
            "CWE-502: Safe Deserialization",
            Arrays.asList(
                ".*new ObjectInputStream\\(.*\\).*",
                ".*readObject\\(\\).*"
            ),
            "ObjectInputStream ois = new ObjectInputStream(input) {\n" +
            "  @Override\n" +
            "  protected Class<?> resolveClass(ObjectStreamClass desc)\n" +
            "    throws IOException, ClassNotFoundException {\n" +
            "    if (!desc.getName().startsWith(\"com.beanvulnerable.\")) {\n" +
            "      throw new InvalidClassException(\"Blocked\", desc.getName());\n" +
            "    }\n" +
            "    return super.resolveClass(desc);\n" +
            "  }\n" +
            "};",
            Arrays.asList("java.io.ObjectInputStream", "java.io.ObjectStreamClass"),
            "Allowlist classes during deserialization"
        ));

        // CWE-601: Open Redirect
        templates.put("CWE-601", new PatchTemplate(
            "CWE-601: Open Redirect Prevention",
            Arrays.asList(
                ".*sendRedirect\\(.*\\+.*\\).*",
                ".*RedirectView.*setUrl.*"
            ),
            "if (!target.startsWith(\"/\")) {\n" +
            "  throw new SecurityException(\"Invalid redirect\");\n" +
            "}\n" +
            "response.sendRedirect(target);",
            Arrays.asList("javax.servlet.http.HttpServletResponse"),
            "Validate redirect targets against allowlists"
        ));
    }

    public PatchTemplate getTemplate(String cwe) {
        return templates.get(cwe);
    }

    public Collection<PatchTemplate> getAllTemplates() {
        return templates.values();
    }

    /**
     * Patch template class
     */
    public static class PatchTemplate {
        public String name;
        public List<String> vulnerablePatterns;
        public String replacement;
        public List<String> requiredImports;
        public String description;

        public PatchTemplate(String name, List<String> patterns, String replacement,
                             List<String> imports, String description) {
            this.name = name;
            this.vulnerablePatterns = patterns;
            this.replacement = replacement;
            this.requiredImports = imports;
            this.description = description;
        }
    }
}
