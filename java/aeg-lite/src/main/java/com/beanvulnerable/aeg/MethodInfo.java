package com.beanvulnerable.aeg;

public class MethodInfo {
    private final String name;
    private final String descriptor;

    public MethodInfo(String name, String descriptor) {
        this.name = name;
        this.descriptor = descriptor;
    }

    public String getName() {
        return name;
    }

    public String getDescriptor() {
        return descriptor;
    }
}
