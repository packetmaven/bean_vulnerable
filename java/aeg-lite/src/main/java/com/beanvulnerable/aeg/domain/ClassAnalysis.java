package com.beanvulnerable.aeg.domain;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

// ============================================
// ClassAnalysis: Complete class analysis
// ============================================
public class ClassAnalysis {
    private final String className;
    private final Map<String, MethodAnalysis> methodAnalyses;
    private final List<String> vulnerabilities;

    public ClassAnalysis(String className) {
        this.className = className;
        this.methodAnalyses = new HashMap<>();
        this.vulnerabilities = new ArrayList<>();
    }

    public void addMethodAnalysis(MethodAnalysis analysis) {
        if (analysis != null) {
            methodAnalyses.put(analysis.getMethodName(), analysis);
        }
    }

    public String getClassName() {
        return className;
    }

    public Map<String, MethodAnalysis> getMethodAnalyses() {
        return methodAnalyses;
    }

    public List<String> getVulnerabilities() {
        return vulnerabilities;
    }

    public void addVulnerability(String vulnerabilityId) {
        if (vulnerabilityId != null && !vulnerabilityId.isEmpty()) {
            vulnerabilities.add(vulnerabilityId);
        }
    }
}
