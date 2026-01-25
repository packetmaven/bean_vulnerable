package com.beanvulnerable.aeg.domain;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

// ============================================
// ExecutionPath: Collected symbolic execution state
// ============================================
public class ExecutionPath {
    private final List<Constraint> constraints = new ArrayList<>();
    private final Map<String, SymbolicValue> symbolicValues = new HashMap<>();
    private final List<DataFlowSource> sources = new ArrayList<>();
    private final List<DataFlowSink> sinks = new ArrayList<>();
    private final List<Vulnerability> vulnerabilities = new ArrayList<>();

    public void addConstraint(Constraint constraint) {
        if (constraint != null) {
            constraints.add(constraint);
        }
    }

    public List<Constraint> getConstraints() {
        return constraints;
    }

    public void addSymbolicValue(String name, SymbolicValue value) {
        if (name != null && value != null) {
            symbolicValues.put(name, value);
        }
    }

    public Map<String, SymbolicValue> getSymbolicValues() {
        return symbolicValues;
    }

    public void addSource(DataFlowSource source) {
        if (source != null) {
            sources.add(source);
        }
    }

    public void addSink(DataFlowSink sink) {
        if (sink != null) {
            sinks.add(sink);
        }
    }

    public List<DataFlowSource> getSources() {
        return sources;
    }

    public List<DataFlowSink> getSinks() {
        return sinks;
    }

    public void addVulnerability(Vulnerability vulnerability) {
        if (vulnerability != null) {
            vulnerabilities.add(vulnerability);
        }
    }

    public List<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }
}
