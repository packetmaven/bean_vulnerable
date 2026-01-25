package com.beanvulnerable.aeg;

import com.beanvulnerable.aeg.domain.Vulnerability;

import java.util.ArrayList;
import java.util.List;

public class SymbolicAnalysisResult {
    private final String className;
    private final List<Vulnerability> vulnerabilities = new ArrayList<>();

    public SymbolicAnalysisResult(String className) {
        this.className = className;
    }

    public void addVulnerability(Vulnerability vulnerability) {
        if (vulnerability != null) {
            vulnerabilities.add(vulnerability);
        }
    }

    public String getClassName() {
        return className;
    }

    public List<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }
}
