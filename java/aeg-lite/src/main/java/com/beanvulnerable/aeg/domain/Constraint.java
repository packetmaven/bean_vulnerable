package com.beanvulnerable.aeg.domain;

// ============================================
// Constraint: SMT-LIB constraint container
// ============================================
public class Constraint {
    private final String id;
    private final String expression;

    public Constraint(String id, String expression) {
        this.id = id;
        this.expression = expression;
    }

    public String getId() {
        return id;
    }

    public String getExpression() {
        return expression;
    }
}
