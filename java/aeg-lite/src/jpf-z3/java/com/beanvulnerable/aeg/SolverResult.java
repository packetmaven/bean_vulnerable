package com.beanvulnerable.aeg;

import java.util.HashMap;
import java.util.Map;

public class SolverResult {
    private SolverStatus status = SolverStatus.UNKNOWN;
    private Map<String, Object> model = new HashMap<>();

    public SolverStatus getStatus() {
        return status;
    }

    public void setStatus(SolverStatus status) {
        this.status = status;
    }

    public Map<String, Object> getModel() {
        return model;
    }

    public void setModel(Map<String, Object> model) {
        this.model = model;
    }
}
