package com.beanvulnerable.aeg.domain;

// ============================================
// DataFlowSink: Dangerous operation
// ============================================
public class DataFlowSink {
    private final String sinkId;
    private final String className;
    private final String methodName;
    private final String sinkType; // "sql_injection", "command_injection", etc.

    public DataFlowSink(String sinkId, String className, String methodName, String sinkType) {
        this.sinkId = sinkId;
        this.className = className;
        this.methodName = methodName;
        this.sinkType = sinkType;
    }

    public String getSinkId() {
        return sinkId;
    }

    public String getClassName() {
        return className;
    }

    public String getMethodName() {
        return methodName;
    }

    public String getSinkType() {
        return sinkType;
    }
}
