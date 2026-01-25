package com.beanvulnerable.aeg;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class TemplateRegistry {

    private final Map<String, ExploitTemplate> templates;

    public TemplateRegistry() {
        this.templates = new HashMap<>();
        registerDefaultTemplates();
    }

    private void registerDefaultTemplates() {
        templates.put("sql_injection",
            new ExploitTemplate(
                "sql_injection",
                "SQL Injection PoC",
                "sql_injection",
                ExploitTemplate.SQL_INJECTION_TEMPLATE
            ));

        templates.put("command_injection",
            new ExploitTemplate(
                "command_injection",
                "Command Injection PoC",
                "command_injection",
                ExploitTemplate.COMMAND_INJECTION_TEMPLATE
            ));

        templates.put("path_traversal",
            new ExploitTemplate(
                "path_traversal",
                "Path Traversal PoC",
                "path_traversal",
                ExploitTemplate.PATH_TRAVERSAL_TEMPLATE
            ));

        templates.put("xpath_injection",
            new ExploitTemplate(
                "xpath_injection",
                "XPath Injection PoC",
                "xpath_injection",
                ExploitTemplate.XPATH_INJECTION_TEMPLATE
            ));

        templates.put("xss",
            new ExploitTemplate(
                "xss",
                "XSS PoC",
                "xss",
                ExploitTemplate.XSS_TEMPLATE
            ));

        templates.put("deserialization",
            new ExploitTemplate(
                "deserialization",
                "Deserialization RCE PoC",
                "deserialization",
                ExploitTemplate.DESERIALIZATION_TEMPLATE
            ));

        templates.put("ldap_injection",
            new ExploitTemplate(
                "ldap_injection",
                "LDAP Injection PoC",
                "ldap_injection",
                ExploitTemplate.LDAP_INJECTION_TEMPLATE
            ));

        templates.put("xxe",
            new ExploitTemplate(
                "xxe",
                "XXE PoC",
                "xxe",
                ExploitTemplate.XXE_TEMPLATE
            ));

        templates.put("el_injection",
            new ExploitTemplate(
                "el_injection",
                "EL Injection PoC",
                "el_injection",
                ExploitTemplate.EL_INJECTION_TEMPLATE
            ));

        templates.put("http_response_splitting",
            new ExploitTemplate(
                "http_response_splitting",
                "HTTP Response Splitting PoC",
                "http_response_splitting",
                ExploitTemplate.HTTP_RESPONSE_SPLITTING_TEMPLATE
            ));

        templates.put("url_redirect",
            new ExploitTemplate(
                "url_redirect",
                "Open Redirect PoC",
                "url_redirect",
                ExploitTemplate.URL_REDIRECT_TEMPLATE
            ));

        templates.put("reflection",
            new ExploitTemplate(
                "reflection",
                "Reflection Injection PoC",
                "reflection",
                ExploitTemplate.REFLECTION_INJECTION_TEMPLATE
            ));

        templates.put("reflection_injection",
            new ExploitTemplate(
                "reflection_injection",
                "Reflection Injection PoC",
                "reflection_injection",
                ExploitTemplate.REFLECTION_INJECTION_TEMPLATE
            ));

        templates.put("file_operation",
            new ExploitTemplate(
                "file_operation",
                "File Operation PoC",
                "file_operation",
                ExploitTemplate.FILE_OPERATION_TEMPLATE
            ));
    }

    public ExploitTemplate getTemplate(String vulnerabilityType) {
        return templates.get(vulnerabilityType);
    }

    public Collection<ExploitTemplate> getAllTemplates() {
        return templates.values();
    }

    public void registerTemplate(String key, ExploitTemplate template) {
        templates.put(key, template);
    }
}
