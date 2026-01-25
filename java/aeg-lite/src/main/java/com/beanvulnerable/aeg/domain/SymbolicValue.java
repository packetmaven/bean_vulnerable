package com.beanvulnerable.aeg.domain;

// ============================================
// SymbolicValue: Represents a symbolic variable
// ============================================
public class SymbolicValue {
    private final String name;
    private final String type;
    private final Object concreteValue;

    public SymbolicValue(String name, String type, Object concreteValue) {
        this.name = name;
        this.type = type;
        this.concreteValue = concreteValue;
    }

    public String getName() {
        return name;
    }

    public String getType() {
        return type;
    }

    public Object getConcreteValue() {
        return concreteValue;
    }
}
