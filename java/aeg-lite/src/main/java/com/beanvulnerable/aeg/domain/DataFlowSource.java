package com.beanvulnerable.aeg.domain;

// ============================================
// DataFlowSource: Untrusted input point
// ============================================
public class DataFlowSource {
    private final String sourceId;
    private final String dataType;
    private final String sourceMethod;
    private final String sourceType; // "method_parameter", "network_source", etc.

    public DataFlowSource(String sourceId, String dataType, String sourceMethod, String sourceType) {
        this.sourceId = sourceId;
        this.dataType = dataType;
        this.sourceMethod = sourceMethod;
        this.sourceType = sourceType;
    }

    public String getSourceId() {
        return sourceId;
    }

    public String getDataType() {
        return dataType;
    }

    public String getSourceMethod() {
        return sourceMethod;
    }

    public String getSourceType() {
        return sourceType;
    }
}
