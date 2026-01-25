package com.beanvulnerable.aeg;

public class PatchTemplate {
    private final String templateId;
    private final String vulnerabilityType;
    private final String vulnerablePattern;
    private final String fixedPattern;
    private final int priority;

    public PatchTemplate(String templateId, String vulnerabilityType,
                         String vulnerablePattern, String fixedPattern,
                         int priority) {
        this.templateId = templateId;
        this.vulnerabilityType = vulnerabilityType;
        this.vulnerablePattern = vulnerablePattern;
        this.fixedPattern = fixedPattern;
        this.priority = priority;
    }

    public String getTemplateId() {
        return templateId;
    }

    public String getVulnerabilityType() {
        return vulnerabilityType;
    }

    public String getVulnerablePattern() {
        return vulnerablePattern;
    }

    public String getFixedPattern() {
        return fixedPattern;
    }

    public int getPriority() {
        return priority;
    }
}
