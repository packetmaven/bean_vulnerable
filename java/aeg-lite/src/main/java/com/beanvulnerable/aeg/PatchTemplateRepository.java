package com.beanvulnerable.aeg;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

public class PatchTemplateRepository {

    private final List<PatchTemplate> templates;

    public PatchTemplateRepository() {
        this.templates = new ArrayList<>();
        initializeDefaultTemplates();
    }

    private void initializeDefaultTemplates() {
        templates.add(new PatchTemplate(
            "sql_000",
            "sql_injection",
            "(?s)String\\s+query\\s*=.*?\\+\\s*(\\w+)\\s*\\+.*?\\+\\s*(\\w+)\\s*\\+.*?;\\s*executeQuery\\(query\\);",
            "$1 = $1.replace(\\\"'\\\", \\\"''\\\");\n" +
                "$2 = $2.replace(\\\"'\\\", \\\"''\\\");\n" +
                "String query = \\\"SELECT * FROM users WHERE username = '\\\" + $1 + \\\"' AND password = '\\\" + $2 + \\\"'\\\";\n" +
                "executeQuery(query);",
            110
        ));

        templates.add(new PatchTemplate(
            "sql_001",
            "sql_injection",
            "Statement stmt = .*?;\\s*String query = \\\".*?\\\" \\+ (\\w+);\\s*ResultSet rs = stmt.executeQuery\\(query\\);",
            "PreparedStatement stmt = conn.prepareStatement(\\\"SELECT * FROM users WHERE id = ?\\\");\n" +
                "stmt.setString(1, $1);\n" +
                "ResultSet rs = stmt.executeQuery();",
            100
        ));

        templates.add(new PatchTemplate(
            "cmd_001",
            "command_injection",
            "Runtime\\.getRuntime\\(\\)\\.exec\\(\\\"(.*?)\\\" \\+ (\\w+)\\);",
            "ProcessBuilder pb = new ProcessBuilder(\\\"$1\\\", $2);\n" +
                "pb.start();",
            100
        ));

        templates.add(new PatchTemplate(
            "cmd_002",
            "command_injection",
            "Runtime\\.getRuntime\\(\\)\\.exec\\((\\w+)\\);",
            "ProcessBuilder pb = new ProcessBuilder($1.split(\\\" \\\") );\n" +
                "pb.start();",
            90
        ));

        templates.add(new PatchTemplate(
            "xss_write_001",
            "xss",
            "(?s)(getWriter\\(\\)\\.write)\\(([^;]*?)\\+\\s*(\\w+)\\s*\\+([^;]*?)\\);",
            "$1($2 + $3.replace(\\\"&\\\", \\\"&amp;\\\")" +
                ".replace(\\\"<\\\", \\\"&lt;\\\")" +
                ".replace(\\\">\\\", \\\"&gt;\\\")" +
                ".replace(\\\"\\\\\\\"\\\", \\\"&quot;\\\")" +
                ".replace(\\\"'\\\", \\\"&#x27;\\\") + $4);",
            110
        ));

        templates.add(new PatchTemplate(
            "xss_write_002",
            "xss",
            "(?s)(getWriter\\(\\)\\.write)\\(([^;]*?)\\+\\s*(\\w+)\\s*\\);",
            "$1($2 + $3.replace(\\\"&\\\", \\\"&amp;\\\")" +
                ".replace(\\\"<\\\", \\\"&lt;\\\")" +
                ".replace(\\\">\\\", \\\"&gt;\\\")" +
                ".replace(\\\"\\\\\\\"\\\", \\\"&quot;\\\")" +
                ".replace(\\\"'\\\", \\\"&#x27;\\\"));",
            105
        ));

        templates.add(new PatchTemplate(
            "xss_write_003",
            "xss",
            "(?s)(getWriter\\(\\)\\.write)\\((\\w+)\\);",
            "$1($2.replace(\\\"&\\\", \\\"&amp;\\\")" +
                ".replace(\\\"<\\\", \\\"&lt;\\\")" +
                ".replace(\\\">\\\", \\\"&gt;\\\")" +
                ".replace(\\\"\\\\\\\"\\\", \\\"&quot;\\\")" +
                ".replace(\\\"'\\\", \\\"&#x27;\\\"));",
            100
        ));

        templates.add(new PatchTemplate(
            "xss_println_001",
            "xss",
            "(?s)(getWriter\\(\\)\\.println)\\(([^;]*?)\\+\\s*(\\w+)\\s*\\+([^;]*?)\\);",
            "$1($2 + $3.replace(\\\"&\\\", \\\"&amp;\\\")" +
                ".replace(\\\"<\\\", \\\"&lt;\\\")" +
                ".replace(\\\">\\\", \\\"&gt;\\\")" +
                ".replace(\\\"\\\\\\\"\\\", \\\"&quot;\\\")" +
                ".replace(\\\"'\\\", \\\"&#x27;\\\") + $4);",
            110
        ));

        templates.add(new PatchTemplate(
            "xss_println_002",
            "xss",
            "(?s)(getWriter\\(\\)\\.println)\\(([^;]*?)\\+\\s*(\\w+)\\s*\\);",
            "$1($2 + $3.replace(\\\"&\\\", \\\"&amp;\\\")" +
                ".replace(\\\"<\\\", \\\"&lt;\\\")" +
                ".replace(\\\">\\\", \\\"&gt;\\\")" +
                ".replace(\\\"\\\\\\\"\\\", \\\"&quot;\\\")" +
                ".replace(\\\"'\\\", \\\"&#x27;\\\"));",
            105
        ));

        templates.add(new PatchTemplate(
            "xss_println_003",
            "xss",
            "(?s)(getWriter\\(\\)\\.println)\\((\\w+)\\);",
            "$1($2.replace(\\\"&\\\", \\\"&amp;\\\")" +
                ".replace(\\\"<\\\", \\\"&lt;\\\")" +
                ".replace(\\\">\\\", \\\"&gt;\\\")" +
                ".replace(\\\"\\\\\\\"\\\", \\\"&quot;\\\")" +
                ".replace(\\\"'\\\", \\\"&#x27;\\\"));",
            100
        ));

        templates.add(new PatchTemplate(
            "xss_print_001",
            "xss",
            "(?s)(getWriter\\(\\)\\.print)\\(([^;]*?)\\+\\s*(\\w+)\\s*\\+([^;]*?)\\);",
            "$1($2 + $3.replace(\\\"&\\\", \\\"&amp;\\\")" +
                ".replace(\\\"<\\\", \\\"&lt;\\\")" +
                ".replace(\\\">\\\", \\\"&gt;\\\")" +
                ".replace(\\\"\\\\\\\"\\\", \\\"&quot;\\\")" +
                ".replace(\\\"'\\\", \\\"&#x27;\\\") + $4);",
            110
        ));

        templates.add(new PatchTemplate(
            "xss_print_002",
            "xss",
            "(?s)(getWriter\\(\\)\\.print)\\(([^;]*?)\\+\\s*(\\w+)\\s*\\);",
            "$1($2 + $3.replace(\\\"&\\\", \\\"&amp;\\\")" +
                ".replace(\\\"<\\\", \\\"&lt;\\\")" +
                ".replace(\\\">\\\", \\\"&gt;\\\")" +
                ".replace(\\\"\\\\\\\"\\\", \\\"&quot;\\\")" +
                ".replace(\\\"'\\\", \\\"&#x27;\\\"));",
            105
        ));

        templates.add(new PatchTemplate(
            "xss_print_003",
            "xss",
            "(?s)(getWriter\\(\\)\\.print)\\((\\w+)\\);",
            "$1($2.replace(\\\"&\\\", \\\"&amp;\\\")" +
                ".replace(\\\"<\\\", \\\"&lt;\\\")" +
                ".replace(\\\">\\\", \\\"&gt;\\\")" +
                ".replace(\\\"\\\\\\\"\\\", \\\"&quot;\\\")" +
                ".replace(\\\"'\\\", \\\"&#x27;\\\"));",
            100
        ));

        templates.add(new PatchTemplate(
            "path_001",
            "path_traversal",
            "Files\\.readAllBytes\\(Paths\\.get\\((\\w+)\\)\\)",
            "Files.readAllBytes(assertAllowedPath(Paths.get($1)))",
            90
        ));

        templates.add(new PatchTemplate(
            "xpath_002",
            "xpath_injection",
            "(?s)XPath\\s+(\\w+)\\s*=\\s*XPathFactory\\.newInstance\\(\\)\\.newXPath\\(\\);\\s*String\\s+(\\w+)\\s*=\\s*\"([^\"]*)'\"\\s*\\+\\s*(\\w+)\\s*\\+\\s*\"'([^\"]*)'\"\\s*\\+\\s*(\\w+)\\s*\\+\\s*\"'([^\"]*)\";",
            "XPath $1 = XPathFactory.newInstance().newXPath();\n" +
                "$1.setXPathVariableResolver(new javax.xml.xpath.XPathVariableResolver() {\n" +
                "    @Override\n" +
                "    public Object resolveVariable(javax.xml.namespace.QName variableName) {\n" +
                "        if (\\\"$4\\\".equals(variableName.getLocalPart())) {\n" +
                "            return $4;\n" +
                "        }\n" +
                "        if (\\\"$6\\\".equals(variableName.getLocalPart())) {\n" +
                "            return $6;\n" +
                "        }\n" +
                "        return null;\n" +
                "    }\n" +
                "});\n" +
                "String $2 = \\\"$3\\$$4$5\\$$6$7\\\";",
            95
        ));

        templates.add(new PatchTemplate(
            "xpath_003",
            "xpath_injection",
            "(?s)XPath\\s+(\\w+)\\s*=\\s*XPathFactory\\.newInstance\\(\\)\\.newXPath\\(\\);\\s*String\\s+(\\w+)\\s*=\\s*\"([^\"]*)'\"\\s*\\+\\s*(\\w+)\\s*\\+\\s*\"'([^\"]*)\";",
            "XPath $1 = XPathFactory.newInstance().newXPath();\n" +
                "$1.setXPathVariableResolver(new javax.xml.xpath.XPathVariableResolver() {\n" +
                "    @Override\n" +
                "    public Object resolveVariable(javax.xml.namespace.QName variableName) {\n" +
                "        if (\\\"$4\\\".equals(variableName.getLocalPart())) {\n" +
                "            return $4;\n" +
                "        }\n" +
                "        return null;\n" +
                "    }\n" +
                "});\n" +
                "String $2 = \\\"$3\\$$4$5\\\";",
            92
        ));

        templates.add(new PatchTemplate(
            "xpath_004",
            "xpath_injection",
            "(?s)String\\s+(\\w+)\\s*=\\s*\"([^\"]*)'\"\\s*\\+\\s*(\\w+)\\s*\\+\\s*\"'([^\"]*)'\"\\s*\\+\\s*(\\w+)\\s*\\+\\s*\"'([^\"]*)\";",
            "String $1 = \\\"$2\\\" + escapeXPathLiteral($3) + \\\"$4\\\" + escapeXPathLiteral($5) + \\\"$6\\\";",
            90
        ));

        templates.add(new PatchTemplate(
            "xpath_005",
            "xpath_injection",
            "(?s)String\\s+(\\w+)\\s*=\\s*\"([^\"]*)'\"\\s*\\+\\s*(\\w+)\\s*\\+\\s*\"'([^\"]*)\";",
            "String $1 = \\\"$2\\\" + escapeXPathLiteral($3) + \\\"$4\\\";",
            88
        ));

        templates.add(new PatchTemplate(
            "xpath_006",
            "xpath_injection",
            "(?s)([\\w\\.]+)\\.evaluate\\(\"([^\"]*)'\"\\s*\\+\\s*(\\w+)\\s*\\+\\s*\"'([^\"]*)\"",
            "$1.evaluate(\\\"$2\\\" + escapeXPathLiteral($3) + \\\"$4\\\"",
            87
        ));

        templates.add(new PatchTemplate(
            "xpath_007",
            "xpath_injection",
            "(?s)([\\w\\.]+)\\.evaluate\\(\"([^\"]*)'\"\\s*\\+\\s*(\\w+)\\s*\\+\\s*\"'([^\"]*)'\"\\s*\\+\\s*(\\w+)\\s*\\+\\s*\"'([^\"]*)\"",
            "$1.evaluate(\\\"$2\\\" + escapeXPathLiteral($3) + \\\"$4\\\" + escapeXPathLiteral($5) + \\\"$6\\\"",
            88
        ));

        templates.add(new PatchTemplate(
            "xpath_008",
            "xpath_injection",
            "(?s)([\\w\\.]+)\\.compile\\(\"([^\"]*)'\"\\s*\\+\\s*(\\w+)\\s*\\+\\s*\"'([^\"]*)\"",
            "$1.compile(\\\"$2\\\" + escapeXPathLiteral($3) + \\\"$4\\\"",
            85
        ));

        templates.add(new PatchTemplate(
            "xpath_009",
            "xpath_injection",
            "(?s)([\\w\\.]+)\\.compile\\(\"([^\"]*)'\"\\s*\\+\\s*(\\w+)\\s*\\+\\s*\"'([^\"]*)'\"\\s*\\+\\s*(\\w+)\\s*\\+\\s*\"'([^\"]*)\"",
            "$1.compile(\\\"$2\\\" + escapeXPathLiteral($3) + \\\"$4\\\" + escapeXPathLiteral($5) + \\\"$6\\\"",
            86
        ));

        templates.add(new PatchTemplate(
            "xpath_001",
            "xpath_injection",
            "String xpath = \\\"//user\\[name='\\\" \\+ (\\w+) \\+ \\\"'\\]\\\";",
            "String xpath = \\\"//user[name=\\\" + escapeXPathLiteral($1) + \\\"]\\\";",
            80
        ));

        templates.add(new PatchTemplate(
            "path_000",
            "path_traversal",
            "Files\\.readAllBytes\\((\\w+)\\)",
            "Files.readAllBytes(assertAllowedPath($1))",
            95
        ));

        templates.add(new PatchTemplate(
            "path_002",
            "path_traversal",
            "(?s)Files\\.write\\(([^,]+),\\s*(.+?)\\)",
            "Files.write(assertAllowedPath($1), $2)",
            90
        ));

        templates.add(new PatchTemplate(
            "path_003",
            "path_traversal",
            "(?s)Files\\.write\\(Paths\\.get\\((.+?)\\),\\s*(.+?)\\)",
            "Files.write(assertAllowedPath(Paths.get($1)), $2)",
            90
        ));

        templates.add(new PatchTemplate(
            "path_010",
            "path_traversal",
            "(?s)new\\s+FileInputStream\\(([^,\\)]+)([^\\)]*)\\)",
            "new FileInputStream(assertAllowedPath($1).toFile()$2)",
            92
        ));

        templates.add(new PatchTemplate(
            "path_011",
            "path_traversal",
            "(?s)new\\s+FileOutputStream\\(([^,\\)]+)([^\\)]*)\\)",
            "new FileOutputStream(assertAllowedPath($1).toFile()$2)",
            92
        ));

        templates.add(new PatchTemplate(
            "path_012",
            "path_traversal",
            "(?s)Files\\.newInputStream\\(([^,\\)]+)([^\\)]*)\\)",
            "Files.newInputStream(assertAllowedPath($1)$2)",
            92
        ));

        templates.add(new PatchTemplate(
            "path_013",
            "path_traversal",
            "(?s)Files\\.newOutputStream\\(([^,\\)]+)([^\\)]*)\\)",
            "Files.newOutputStream(assertAllowedPath($1)$2)",
            92
        ));

        templates.add(new PatchTemplate(
            "path_014",
            "path_traversal",
            "(?s)new\\s+FileReader\\(([^,\\)]+)([^\\)]*)\\)",
            "new FileReader(assertAllowedPath($1).toFile()$2)",
            90
        ));

        templates.add(new PatchTemplate(
            "path_015",
            "path_traversal",
            "(?s)new\\s+FileWriter\\(([^,\\)]+)([^\\)]*)\\)",
            "new FileWriter(assertAllowedPath($1).toFile()$2)",
            90
        ));

        templates.add(new PatchTemplate(
            "deser_001",
            "deserialization",
            "(?s)ObjectInputStream\\s+(\\w+)\\s*=\\s*new\\s+ObjectInputStream\\(([^\\)]+)\\);",
            "ObjectInputStream $1 = new ObjectInputStream($2) {\n" +
                "    @Override\n" +
                "    protected Class<?> resolveClass(java.io.ObjectStreamClass desc)\n" +
                "        throws java.io.IOException, ClassNotFoundException {\n" +
                "        String name = desc.getName();\n" +
                "        if (!name.startsWith(\\\"com.beanvulnerable.\\\")) {\n" +
                "            throw new java.io.InvalidClassException(\\\"Blocked deserialization\\\", name);\n" +
                "        }\n" +
                "        return super.resolveClass(desc);\n" +
                "    }\n" +
                "};",
            95
        ));

        templates.add(new PatchTemplate(
            "ldap_001",
            "ldap_injection",
            "(?s)(\\w+)\\.search\\(([^,]+),\\s*([^,\\)]+)([^\\)]*)\\)",
            "$1.search($2, escapeLdapFilter($3)$4)",
            100
        ));

        templates.add(new PatchTemplate(
            "el_001",
            "el_injection",
            "(?s)(\\w+)\\.eval\\(([^\\)]+)\\)",
            "$1.eval(sanitizeElExpression($2))",
            100
        ));

        templates.add(new PatchTemplate(
            "el_002",
            "el_injection",
            "(?s)(\\w+)\\.createValueExpression\\(([^,]+),\\s*([^,]+),",
            "$1.createValueExpression($2, sanitizeElExpression($3),",
            95
        ));

        templates.add(new PatchTemplate(
            "el_003",
            "el_injection",
            "(?s)(\\w+)\\.createMethodExpression\\(([^,]+),\\s*([^,]+),",
            "$1.createMethodExpression($2, sanitizeElExpression($3),",
            95
        ));

        templates.add(new PatchTemplate(
            "xxe_001",
            "xxe",
            "DocumentBuilderFactory\\s+(\\w+)\\s*=\\s*DocumentBuilderFactory\\.newInstance\\(\\);",
            "DocumentBuilderFactory $1 = secureDocumentBuilderFactory();",
            100
        ));

        templates.add(new PatchTemplate(
            "xxe_002",
            "xxe",
            "SAXParserFactory\\s+(\\w+)\\s*=\\s*SAXParserFactory\\.newInstance\\(\\);",
            "SAXParserFactory $1 = secureSaxParserFactory();",
            98
        ));

        templates.add(new PatchTemplate(
            "xxe_003",
            "xxe",
            "XMLInputFactory\\s+(\\w+)\\s*=\\s*XMLInputFactory\\.newInstance\\(\\);",
            "XMLInputFactory $1 = secureXmlInputFactory();",
            96
        ));

        templates.add(new PatchTemplate(
            "http_001",
            "http_response_splitting",
            "(?s)(\\w+)\\.setHeader\\(\\\"([^\\\"]+)\\\",\\s*([^\\)]+)\\);",
            "$1.setHeader(\\\"$2\\\", sanitizeHeaderValue($3));",
            100
        ));

        templates.add(new PatchTemplate(
            "http_002",
            "http_response_splitting",
            "(?s)(\\w+)\\.addHeader\\(\\\"([^\\\"]+)\\\",\\s*([^\\)]+)\\);",
            "$1.addHeader(\\\"$2\\\", sanitizeHeaderValue($3));",
            98
        ));

        templates.add(new PatchTemplate(
            "http_003",
            "http_response_splitting",
            "(?s)(\\w+)\\.sendRedirect\\(([^\\)]+)\\);",
            "$1.sendRedirect(sanitizeRedirectTarget($2));",
            96
        ));

        templates.add(new PatchTemplate(
            "redirect_001",
            "url_redirect",
            "(?s)(\\w+)\\.setHeader\\(\\\"Location\\\",\\s*([^\\)]+)\\);",
            "$1.setHeader(\\\"Location\\\", sanitizeRedirectTarget($2));",
            100
        ));

        templates.add(new PatchTemplate(
            "redirect_002",
            "url_redirect",
            "(?s)(\\w+)\\.addHeader\\(\\\"Location\\\",\\s*([^\\)]+)\\);",
            "$1.addHeader(\\\"Location\\\", sanitizeRedirectTarget($2));",
            98
        ));

        templates.add(new PatchTemplate(
            "redirect_003",
            "url_redirect",
            "(?s)(\\w+)\\.sendRedirect\\(([^\\)]+)\\);",
            "$1.sendRedirect(sanitizeRedirectTarget($2));",
            96
        ));

        templates.add(new PatchTemplate(
            "refl_inj_001",
            "reflection_injection",
            "Class<\\?>\\s+(\\w+)\\s*=\\s*Class\\.forName\\(\\\"([^\\\"]+)\\\"\\);",
            "String allowedClassName = assertAllowedClass(\\\"$2\\\");\n" +
                "Class<?> $1 = Class.forName(allowedClassName);",
            100
        ));

        templates.add(new PatchTemplate(
            "refl_inj_002",
            "reflection_injection",
            "Class<\\?>\\s+(\\w+)\\s*=\\s*Class\\.forName\\(([^\\)]+)\\);",
            "String allowedClassName = assertAllowedClass($2);\n" +
                "Class<?> $1 = Class.forName(allowedClassName);",
            95
        ));

        templates.add(new PatchTemplate(
            "refl_inj_003",
            "reflection_injection",
            "(?s)(\\w+)\\.invoke\\(([^,]+),\\s*([^\\)]+)\\);",
            "if (!isAllowedReflectionTarget($1)) {\n" +
                "    throw new SecurityException(\\\"Invalid reflection target\\\");\n" +
                "}\n" +
                "$1.invoke($2, $3);",
            90
        ));

        templates.add(new PatchTemplate(
            "file_001",
            "file_operation",
            "(?s)new\\s+FileOutputStream\\(([^,\\)]+)([^\\)]*)\\)",
            "new FileOutputStream(assertAllowedPath($1).toFile()$2)",
            90
        ));

        templates.add(new PatchTemplate(
            "refl_001",
            "reflection",
            "Class<\\?>\\s+(\\w+)\\s*=\\s*Class\\.forName\\(\\\"([^\\\"]+)\\\"\\);",
            "String allowedClassName = \\\"$2\\\";\n" +
                "if (!allowedClassName.startsWith(\\\"com.beanvulnerable.\\\")) {\n" +
                "    throw new SecurityException(\\\"Invalid class: \\\" + allowedClassName);\n" +
                "}\n" +
                "Class<?> $1 = Class.forName(allowedClassName);",
            95
        ));
    }

    public List<PatchTemplate> findTemplates(String vulnerabilityType) {
        return templates.stream()
            .filter(t -> t.getVulnerabilityType().equals(vulnerabilityType))
            .sorted(Comparator.comparingInt(PatchTemplate::getPriority).reversed())
            .collect(Collectors.toList());
    }
}
