package com.beanvulnerable.aeg.domain;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

// ============================================
// MethodAnalysis: Complete method analysis
// ============================================
public class MethodAnalysis {
    private final String methodName;
    private final String methodDescriptor;
    private ControlFlowGraph cfg;
    private final Set<DataFlowSource> sources;
    private final Set<DataFlowSink> sinks;
    private final List<String> vulnerabilityPatterns;

    public MethodAnalysis(String methodName, String methodDescriptor) {
        this.methodName = methodName;
        this.methodDescriptor = methodDescriptor;
        this.sources = new HashSet<>();
        this.sinks = new HashSet<>();
        this.vulnerabilityPatterns = new ArrayList<>();
    }

    public String getMethodName() {
        return methodName;
    }

    public String getMethodDescriptor() {
        return methodDescriptor;
    }

    public ControlFlowGraph getCfg() {
        return cfg;
    }

    public void setCfg(ControlFlowGraph cfg) {
        this.cfg = cfg;
    }

    public Set<DataFlowSource> getSources() {
        return sources;
    }

    public Set<DataFlowSink> getSinks() {
        return sinks;
    }

    public List<String> getVulnerabilityPatterns() {
        return vulnerabilityPatterns;
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

    public void addVulnerabilityPattern(String patternId) {
        if (patternId != null && !patternId.isEmpty()) {
            vulnerabilityPatterns.add(patternId);
        }
    }

    public void setSources(Set<DataFlowSource> newSources) {
        sources.clear();
        if (newSources != null) {
            sources.addAll(newSources);
        }
    }

    public void setSinks(Set<DataFlowSink> newSinks) {
        sinks.clear();
        if (newSinks != null) {
            sinks.addAll(newSinks);
        }
    }
}
