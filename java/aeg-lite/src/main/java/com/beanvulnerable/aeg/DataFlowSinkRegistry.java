package com.beanvulnerable.aeg;

import com.beanvulnerable.aeg.domain.DataFlowSink;

import java.util.HashMap;
import java.util.Map;

public class DataFlowSinkRegistry {
    private final Map<String, DataFlowSink> sinks = new HashMap<>();

    public void register(String owner, String methodName, String sinkType) {
        String key = key(owner, methodName);
        String ownerName = owner != null ? owner.replace('/', '.') : "unknown";
        DataFlowSink sink = new DataFlowSink(
            key,
            ownerName,
            methodName != null ? methodName : "unknown",
            sinkType
        );
        sinks.put(key, sink);
    }

    public boolean isSink(String owner, String methodName) {
        return sinks.containsKey(key(owner, methodName));
    }

    public DataFlowSink getSink(String owner, String methodName) {
        return sinks.get(key(owner, methodName));
    }

    private String key(String owner, String methodName) {
        String ownerName = owner != null ? owner : "unknown";
        String method = methodName != null ? methodName : "unknown";
        return ownerName + "#" + method;
    }
}
