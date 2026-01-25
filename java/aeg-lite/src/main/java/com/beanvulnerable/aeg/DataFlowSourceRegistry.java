package com.beanvulnerable.aeg;

import com.beanvulnerable.aeg.domain.DataFlowSource;

import java.util.HashMap;
import java.util.Map;

public class DataFlowSourceRegistry {
    private final Map<String, DataFlowSource> sources = new HashMap<>();

    public void register(String owner, String methodName, String sourceType) {
        String key = key(owner, methodName);
        String ownerName = owner != null ? owner.replace('/', '.') : "unknown";
        DataFlowSource source = new DataFlowSource(
            key,
            "unknown",
            ownerName + "." + methodName,
            sourceType
        );
        sources.put(key, source);
    }

    public boolean isSource(String owner, String methodName) {
        return sources.containsKey(key(owner, methodName));
    }

    public DataFlowSource getSource(String owner, String methodName) {
        return sources.get(key(owner, methodName));
    }

    private String key(String owner, String methodName) {
        String ownerName = owner != null ? owner : "unknown";
        String method = methodName != null ? methodName : "unknown";
        return ownerName + "#" + method;
    }
}
